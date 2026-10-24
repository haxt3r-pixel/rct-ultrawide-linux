#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define APP_NAME "rct-ultrawide"
#define APP_VERSION "0.2.0"
#define SUPPORTED_SHA256 "bdfebd64383b231de0252fe0726523d1c45aa2c4da919c2d7ed8bfb7aaa05c76"
#define PE_IMAGE_BASE 0x00400000u
#define CONFIG_SIZE 100u
#define CONFIG_DISPLAY_MODE_OFFSET 23u
#define PATCH_TIMEOUT_SECONDS 120
#define POLL_INTERVAL_NS 20000000L
#define MAX_DISPLAYS 32
#define MAX_STEAM_LIBRARIES 32
#define MAX_STEAM_CANDIDATES 16

typedef struct {
    uint32_t state[8];
    uint64_t bit_length;
    uint8_t buffer[64];
    size_t buffer_length;
} Sha256Context;

static const uint32_t sha256_round_constants[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static const uint8_t resize_signature[] = {
    0x83, 0x7d, 0xf8, 0x00, 0x0f, 0x84, 0x87, 0x00, 0x00, 0x00,
    0x81, 0x7d, 0xfc, 0x00, 0x05, 0x00, 0x00, 0x7e, 0x07, 0xc7,
    0x45, 0xfc, 0x00, 0x05, 0x00, 0x00, 0x81, 0x7d, 0xf4, 0x00,
    0x04, 0x00, 0x00, 0x7e, 0x07, 0xc7, 0x45, 0xf4, 0x00, 0x04,
    0x00, 0x00
};

static const uint8_t stride_signature[] = {
    0x0f, 0xb7, 0xc0, 0x33, 0xd2, 0x0f, 0xb7, 0x0d, 0xea, 0x59,
    0x8b, 0x00, 0xf7, 0xf1, 0xa3, 0xf0, 0x59, 0x8b, 0x00, 0x0f,
    0xb7, 0xc3, 0x33, 0xd2, 0x0f, 0xb7, 0x0d, 0xe8, 0x59, 0x8b,
    0x00, 0xf7, 0xf1, 0xa3, 0xec, 0x59, 0x8b, 0x00
};

/*
 * Replaces the 19-byte width-stride sequence at RVA 0x24222.
 * ECX is loaded with the actual tile width, then LEA computes
 * width + tile_width - 1 before DIV. This is ceil(width / tile_width)
 * for both 32- and 64-pixel blocks, without assuming a display size.
 */
static const uint8_t stride_patch[] = {
    0x0f, 0xb7, 0x0d, 0xe8, 0x59, 0x8b, 0x00, /* movzx ecx, word [0x8b59e8] */
    0x8d, 0x44, 0x0b, 0xff,                   /* lea eax, [ebx + ecx - 1] */
    0x99,                                       /* cdq; EAX is a positive 16-bit sum */
    0xf7, 0xf1,                                /* div ecx */
    0xa3, 0xec, 0x59, 0x8b, 0x00              /* mov [0x8b59ec], eax */
};

typedef struct {
    uint32_t address;
    uint32_t old_value;
    uint32_t new_value;
} ImmediatePatch;

typedef enum {
    PATCH_PENDING,
    PATCH_SUCCESS,
    PATCH_FATAL
} PatchResult;

typedef struct {
    char name[128];
    uint32_t width;
    uint32_t height;
    long x;
    long y;
    bool primary;
} DisplayInfo;

static void sha256_transform(Sha256Context *ctx, const uint8_t block[64]) {
    uint32_t words[64];
    for (unsigned i = 0; i < 16; ++i) {
        unsigned j = i * 4;
        words[i] = ((uint32_t)block[j] << 24) | ((uint32_t)block[j + 1] << 16) |
                   ((uint32_t)block[j + 2] << 8) | (uint32_t)block[j + 3];
    }
    for (unsigned i = 16; i < 64; ++i) {
        uint32_t s0 = (words[i - 15] >> 7 | words[i - 15] << 25) ^
                      (words[i - 15] >> 18 | words[i - 15] << 14) ^
                      (words[i - 15] >> 3);
        uint32_t s1 = (words[i - 2] >> 17 | words[i - 2] << 15) ^
                      (words[i - 2] >> 19 | words[i - 2] << 13) ^
                      (words[i - 2] >> 10);
        words[i] = words[i - 16] + s0 + words[i - 7] + s1;
    }

    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];
    for (unsigned i = 0; i < 64; ++i) {
        uint32_t s1 = (e >> 6 | e << 26) ^ (e >> 11 | e << 21) ^ (e >> 25 | e << 7);
        uint32_t choose = (e & f) ^ (~e & g);
        uint32_t t1 = h + s1 + choose + sha256_round_constants[i] + words[i];
        uint32_t s0 = (a >> 2 | a << 30) ^ (a >> 13 | a << 19) ^ (a >> 22 | a << 10);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + majority;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(Sha256Context *ctx) {
    static const uint32_t initial[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };
    memcpy(ctx->state, initial, sizeof(initial));
    ctx->bit_length = 0;
    ctx->buffer_length = 0;
}

static void sha256_update(Sha256Context *ctx, const uint8_t *data, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        ctx->buffer[ctx->buffer_length++] = data[i];
        if (ctx->buffer_length == sizeof(ctx->buffer)) {
            sha256_transform(ctx, ctx->buffer);
            ctx->bit_length += 512;
            ctx->buffer_length = 0;
        }
    }
}

static void sha256_final(Sha256Context *ctx, uint8_t digest[32]) {
    size_t i = ctx->buffer_length;
    ctx->buffer[i++] = 0x80;
    if (i > 56) {
        while (i < 64) ctx->buffer[i++] = 0;
        sha256_transform(ctx, ctx->buffer);
        memset(ctx->buffer, 0, 56);
    } else {
        while (i < 56) ctx->buffer[i++] = 0;
    }
    ctx->bit_length += (uint64_t)ctx->buffer_length * 8;
    for (unsigned j = 0; j < 8; ++j)
        ctx->buffer[63 - j] = (uint8_t)(ctx->bit_length >> (j * 8));
    sha256_transform(ctx, ctx->buffer);
    for (unsigned j = 0; j < 8; ++j) {
        digest[j * 4] = (uint8_t)(ctx->state[j] >> 24);
        digest[j * 4 + 1] = (uint8_t)(ctx->state[j] >> 16);
        digest[j * 4 + 2] = (uint8_t)(ctx->state[j] >> 8);
        digest[j * 4 + 3] = (uint8_t)ctx->state[j];
    }
}

static int sha256_file(const char *path, char output[65]) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    Sha256Context ctx;
    sha256_init(&ctx);
    uint8_t buffer[32768], digest[32];
    ssize_t count;
    while ((count = read(fd, buffer, sizeof(buffer))) > 0)
        sha256_update(&ctx, buffer, (size_t)count);
    int saved_errno = errno;
    close(fd);
    if (count < 0) { errno = saved_errno; return -1; }
    sha256_final(&ctx, digest);
    static const char hex[] = "0123456789abcdef";
    for (unsigned i = 0; i < sizeof(digest); ++i) {
        output[i * 2] = hex[digest[i] >> 4];
        output[i * 2 + 1] = hex[digest[i] & 0x0f];
    }
    output[64] = '\0';
    return 0;
}

static uint16_t read_le16(const uint8_t *p) {
    return (uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8);
}

static uint32_t read_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void write_le32(uint8_t *p, uint32_t value) {
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
    p[3] = (uint8_t)(value >> 24);
}

static bool validate_supported_game(const char *input_path, char game_path[PATH_MAX], char *error, size_t error_size) {
    if (!realpath(input_path, game_path)) {
        snprintf(error, error_size, "cannot resolve game executable '%s': %s", input_path, strerror(errno));
        return false;
    }
    const char *basename = strrchr(game_path, '/');
    basename = basename ? basename + 1 : game_path;
    if (strcasecmp(basename, "RCT.EXE") != 0) {
        snprintf(error, error_size, "expected RCT.EXE, got '%s'", basename);
        return false;
    }
    struct stat st;
    if (stat(game_path, &st) != 0 || !S_ISREG(st.st_mode)) {
        snprintf(error, error_size, "game executable is not a regular file: %s", game_path);
        return false;
    }
    char digest[65];
    if (sha256_file(game_path, digest) != 0) {
        snprintf(error, error_size, "cannot hash '%s': %s", game_path, strerror(errno));
        return false;
    }
    if (strcmp(digest, SUPPORTED_SHA256) != 0) {
        snprintf(error, error_size,
                 "unsupported RCT.EXE build (SHA-256 %s). This release only supports %s; no game code was changed.",
                 digest, SUPPORTED_SHA256);
        return false;
    }

    int fd = open(game_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        snprintf(error, error_size, "cannot open '%s': %s", game_path, strerror(errno));
        return false;
    }
    uint8_t dos[64], pe[24], optional[32];
    ssize_t got = pread(fd, dos, sizeof(dos), 0);
    uint32_t pe_offset = got == (ssize_t)sizeof(dos) ? read_le32(dos + 0x3c) : UINT32_MAX;
    bool pe_ok = got == (ssize_t)sizeof(dos) && dos[0] == 'M' && dos[1] == 'Z' &&
                 st.st_size >= 24 && pe_offset <= (uint32_t)(st.st_size - 24) &&
                 pread(fd, pe, sizeof(pe), pe_offset) == (ssize_t)sizeof(pe) &&
                 memcmp(pe, "PE\0\0", 4) == 0 && read_le16(pe + 4) == 0x014c &&
                 read_le16(pe + 20) >= sizeof(optional) &&
                 pread(fd, optional, sizeof(optional), (off_t)pe_offset + 24) == (ssize_t)sizeof(optional) &&
                 read_le16(optional) == 0x010b &&
                 read_le32(optional + 28) == PE_IMAGE_BASE;
    close(fd);
    if (!pe_ok) {
        snprintf(error, error_size, "the supported hash did not have the expected 32-bit PE image layout; refusing to patch");
        return false;
    }
    return true;
}

static bool derive_config_paths(const char *game_path, char config_path[PATH_MAX], char backup_path[PATH_MAX]) {
    char directory[PATH_MAX];
    size_t length = strlen(game_path);
    if (length >= sizeof(directory)) return false;
    memcpy(directory, game_path, length + 1);
    char *slash = strrchr(directory, '/');
    if (!slash) return false;
    *slash = '\0';
    if (snprintf(config_path, PATH_MAX, "%s/Data/Game.cfg", directory) >= PATH_MAX ||
        snprintf(backup_path, PATH_MAX, "%s/Data/Game.cfg.rct-ultrawide.bak", directory) >= PATH_MAX)
        return false;
    return true;
}

static bool read_config(const char *path, uint8_t bytes[CONFIG_SIZE], mode_t *mode, char *error, size_t error_size) {
    struct stat st;
    if (lstat(path, &st) != 0) {
        snprintf(error, error_size, "cannot inspect config '%s': %s", path, strerror(errno));
        return false;
    }
    if (!S_ISREG(st.st_mode)) {
        snprintf(error, error_size, "config is not a regular file (symlinks are refused): %s", path);
        return false;
    }
    if (st.st_size != CONFIG_SIZE) {
        snprintf(error, error_size, "unexpected Game.cfg size (%lld bytes; expected %u); no settings were changed",
                 (long long)st.st_size, CONFIG_SIZE);
        return false;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        snprintf(error, error_size, "cannot read config '%s': %s", path, strerror(errno));
        return false;
    }
    size_t offset = 0;
    while (offset < CONFIG_SIZE) {
        ssize_t got = read(fd, bytes + offset, CONFIG_SIZE - offset);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) {
            int saved_errno = got < 0 ? errno : EIO;
            close(fd);
            snprintf(error, error_size, "short read from config '%s': %s", path, strerror(saved_errno));
            return false;
        }
        offset += (size_t)got;
    }
    close(fd);
    if (bytes[CONFIG_DISPLAY_MODE_OFFSET] > 1) {
        snprintf(error, error_size, "unknown Game.cfg display-mode value %u; no settings were changed",
                 bytes[CONFIG_DISPLAY_MODE_OFFSET]);
        return false;
    }
    if (mode) *mode = st.st_mode & 0777;
    return true;
}

static bool write_all(int fd, const uint8_t *data, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t count = write(fd, data + offset, length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        offset += (size_t)count;
    }
    return true;
}

static bool atomic_write_config(const char *path, const uint8_t bytes[CONFIG_SIZE], mode_t mode,
                               char *error, size_t error_size) {
    char temporary[PATH_MAX];
    if (snprintf(temporary, sizeof(temporary), "%s.rct-ultrawide.tmp.%ld", path, (long)getpid()) >= (int)sizeof(temporary)) {
        snprintf(error, error_size, "config path is too long");
        return false;
    }
    int fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode ? mode : 0600);
    if (fd < 0) {
        snprintf(error, error_size, "cannot create temporary config '%.400s': %s", temporary, strerror(errno));
        return false;
    }
    bool ok = write_all(fd, bytes, CONFIG_SIZE) && fchmod(fd, mode ? mode : 0600) == 0 && fsync(fd) == 0;
    int saved_errno = errno;
    if (close(fd) != 0 && ok) { ok = false; saved_errno = errno; }
    if (!ok) {
        unlink(temporary);
        snprintf(error, error_size, "cannot write temporary config: %s", strerror(saved_errno));
        return false;
    }
    if (rename(temporary, path) != 0) {
        saved_errno = errno;
        unlink(temporary);
        snprintf(error, error_size, "cannot replace config '%s': %s", path, strerror(saved_errno));
        return false;
    }
    char directory[PATH_MAX];
    if (strlen(path) >= sizeof(directory)) return true;
    strcpy(directory, path);
    char *slash = strrchr(directory, '/');
    if (slash) *slash = '\0';
    int dirfd = open(slash ? directory : ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd >= 0) { (void)fsync(dirfd); close(dirfd); }
    return true;
}

static bool ensure_backup(const char *config_path, const char *backup_path,
                          const uint8_t original[CONFIG_SIZE], mode_t mode,
                          char *error, size_t error_size) {
    struct stat st;
    if (lstat(backup_path, &st) == 0) {
        uint8_t backup[CONFIG_SIZE];
        if (!S_ISREG(st.st_mode) || st.st_size != CONFIG_SIZE ||
            !read_config(backup_path, backup, NULL, error, error_size)) {
            if (error[0] == '\0') snprintf(error, error_size, "existing backup is not a valid Game.cfg file: %s", backup_path);
            return false;
        }
        (void)config_path;
        return true;
    }
    if (errno != ENOENT) {
        snprintf(error, error_size, "cannot inspect backup '%s': %s", backup_path, strerror(errno));
        return false;
    }
    int fd = open(backup_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode ? mode : 0600);
    if (fd < 0) {
        if (errno == EEXIST) return ensure_backup(config_path, backup_path, original, mode, error, error_size);
        snprintf(error, error_size, "cannot create backup '%s': %s", backup_path, strerror(errno));
        return false;
    }
    bool ok = write_all(fd, original, CONFIG_SIZE) && fchmod(fd, mode ? mode : 0600) == 0 && fsync(fd) == 0;
    int saved_errno = errno;
    if (close(fd) != 0 && ok) { ok = false; saved_errno = errno; }
    if (!ok) {
        unlink(backup_path);
        snprintf(error, error_size, "cannot save backup '%s': %s", backup_path, strerror(saved_errno));
        return false;
    }
    return true;
}

static bool configure_game(const char *game_path, bool verbose, char *error, size_t error_size) {
    char config_path[PATH_MAX], backup_path[PATH_MAX];
    if (!derive_config_paths(game_path, config_path, backup_path)) {
        snprintf(error, error_size, "cannot build Game.cfg path from '%.400s'", game_path);
        return false;
    }
    uint8_t config[CONFIG_SIZE];
    mode_t mode;
    if (!read_config(config_path, config, &mode, error, error_size)) return false;
    if (!ensure_backup(config_path, backup_path, config, mode, error, error_size)) return false;
    if (config[CONFIG_DISPLAY_MODE_OFFSET] != 0) {
        config[CONFIG_DISPLAY_MODE_OFFSET] = 0;
        if (!atomic_write_config(config_path, config, mode, error, error_size)) return false;
        if (verbose) printf("Selected the windowed GDI renderer in %s (saved original settings to %s).\n", config_path, backup_path);
    } else if (verbose) {
        printf("Game.cfg already selects the windowed GDI renderer. Backup: %s\n", backup_path);
    }
    return true;
}

static bool restore_game_config(const char *game_path, char *error, size_t error_size) {
    char config_path[PATH_MAX], backup_path[PATH_MAX];
    if (!derive_config_paths(game_path, config_path, backup_path)) {
        snprintf(error, error_size, "cannot build Game.cfg path from '%.400s'", game_path);
        return false;
    }
    uint8_t current[CONFIG_SIZE], backup[CONFIG_SIZE];
    mode_t mode;
    if (!read_config(config_path, current, &mode, error, error_size)) return false;
    if (!read_config(backup_path, backup, NULL, error, error_size)) return false;
    if (current[CONFIG_DISPLAY_MODE_OFFSET] == backup[CONFIG_DISPLAY_MODE_OFFSET]) {
        printf("The display-mode flag is already at its backed-up value (%u).\n", backup[CONFIG_DISPLAY_MODE_OFFSET]);
        return true;
    }
    current[CONFIG_DISPLAY_MODE_OFFSET] = backup[CONFIG_DISPLAY_MODE_OFFSET];
    if (!atomic_write_config(config_path, current, mode, error, error_size)) return false;
    printf("Restored only Game.cfg byte %u to its saved value. Other current settings were preserved.\n",
           CONFIG_DISPLAY_MODE_OFFSET);
    return true;
}

static bool parse_dimensions(const char *text, uint32_t *width, uint32_t *height) {
    char extra;
    unsigned w, h;
    if (sscanf(text, "%ux%u%c", &w, &h, &extra) != 2 || w < 320 || h < 200 || w > 32767 || h > 32767)
        return false;
    *width = w;
    *height = h;
    return true;
}

static bool command_exists(const char *command);

static bool parse_display_geometry(const char *text, uint32_t *width, uint32_t *height, long *x, long *y) {
    unsigned parsed_width, parsed_height;
    long parsed_x, parsed_y;
    if (sscanf(text, "%ux%u%ld%ld", &parsed_width, &parsed_height, &parsed_x, &parsed_y) != 4 ||
        parsed_width < 320 || parsed_height < 200 || parsed_width > 32767 || parsed_height > 32767)
        return false;
    *width = parsed_width;
    *height = parsed_height;
    *x = parsed_x;
    *y = parsed_y;
    return true;
}

/*
 * Read active XRandR outputs rather than Screen 0's combined virtual desktop
 * size. That prevents Gamescope from treating two side-by-side displays as a
 * single very wide output. A selected zero-based index is passed to Gamescope;
 * index correspondence across multiple active displays remains unverified.
 */
static bool query_displays(DisplayInfo displays[MAX_DISPLAYS], size_t *count,
                           char *error, size_t error_size) {
    *count = 0;
    if (!command_exists("xrandr")) {
        snprintf(error, error_size, "xrandr was not found in PATH");
        return false;
    }
    FILE *pipe = popen("xrandr --query 2>/dev/null", "r");
    if (!pipe) {
        snprintf(error, error_size, "cannot run xrandr: %s", strerror(errno));
        return false;
    }
    char line[1024];
    while (*count < MAX_DISPLAYS && fgets(line, sizeof(line), pipe)) {
        char *connected = strstr(line, " connected");
        if (!connected) continue;

        size_t name_length = (size_t)(connected - line);
        if (name_length == 0 || name_length >= sizeof(displays[0].name)) continue;
        DisplayInfo parsed = {0};
        memcpy(parsed.name, line, name_length);
        parsed.name[name_length] = '\0';

        char *cursor = connected + strlen(" connected");
        while (isspace((unsigned char)*cursor)) ++cursor;
        if (strncmp(cursor, "primary", 7) == 0 && isspace((unsigned char)cursor[7])) {
            parsed.primary = true;
            cursor += 7;
            while (isspace((unsigned char)*cursor)) ++cursor;
        }
        char geometry[96];
        size_t geometry_length = 0;
        while (cursor[geometry_length] && !isspace((unsigned char)cursor[geometry_length]) &&
               geometry_length + 1 < sizeof(geometry))
            ++geometry_length;
        if (geometry_length == 0) continue;
        memcpy(geometry, cursor, geometry_length);
        geometry[geometry_length] = '\0';
        if (!parse_display_geometry(geometry, &parsed.width, &parsed.height, &parsed.x, &parsed.y)) continue;
        displays[*count] = parsed;
        ++*count;
    }
    int status = pclose(pipe);
    if (status == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        snprintf(error, error_size, "xrandr could not report active displays");
        *count = 0;
        return false;
    }
    if (*count == 0) {
        snprintf(error, error_size, "xrandr found no connected display with an active mode");
        return false;
    }
    return true;
}

static size_t primary_display_index(const DisplayInfo displays[MAX_DISPLAYS], size_t count) {
    for (size_t i = 0; i < count; ++i)
        if (displays[i].primary) return i;
    return 0;
}

static void print_displays(FILE *stream, const DisplayInfo displays[MAX_DISPLAYS], size_t count) {
    for (size_t i = 0; i < count; ++i) {
        fprintf(stream, "  %zu: %s %ux%u at %+ld%+ld%s\n", i, displays[i].name,
                displays[i].width, displays[i].height, displays[i].x, displays[i].y,
                displays[i].primary ? " (primary)" : "");
    }
}

static bool command_exists(const char *command) {
    const char *path = getenv("PATH");
    if (!path || !*path) return false;
    size_t command_length = strlen(command);
    const char *entry = path;
    while (true) {
        const char *end = strchr(entry, ':');
        size_t directory_length = end ? (size_t)(end - entry) : strlen(entry);
        char candidate[PATH_MAX];
        if (directory_length == 0) {
            if (snprintf(candidate, sizeof(candidate), "./%s", command) < (int)sizeof(candidate) && access(candidate, X_OK) == 0)
                return true;
        } else if (directory_length + command_length + 2 < sizeof(candidate)) {
            memcpy(candidate, entry, directory_length);
            candidate[directory_length] = '/';
            memcpy(candidate + directory_length + 1, command, command_length + 1);
            if (access(candidate, X_OK) == 0) return true;
        }
        if (!end) break;
        entry = end + 1;
    }
    return false;
}

static bool shell_quote(const char *input, char output[PATH_MAX * 4]) {
    size_t used = 0;
    if (used + 1 >= PATH_MAX * 4) return false;
    output[used++] = '\'';
    for (const char *p = input; *p; ++p) {
        if (*p == '\'') {
            const char replacement[] = "'\\''";
            if (used + sizeof(replacement) >= PATH_MAX * 4) return false;
            memcpy(output + used, replacement, sizeof(replacement) - 1);
            used += sizeof(replacement) - 1;
        } else {
            if (used + 2 >= PATH_MAX * 4) return false;
            output[used++] = *p;
        }
    }
    output[used++] = '\'';
    output[used] = '\0';
    return true;
}

static bool parse_vdf_value(const char *line, const char *key, char *value, size_t value_size) {
    char token[96];
    if (snprintf(token, sizeof(token), "\"%s\"", key) >= (int)sizeof(token)) return false;
    const char *position = strstr(line, token);
    if (!position) return false;
    position += strlen(token);
    while (isspace((unsigned char)*position)) ++position;
    if (*position != '"') return false;
    ++position;
    size_t used = 0;
    while (*position && *position != '"') {
        char byte = *position++;
        if (byte == '\\' && *position) byte = *position++;
        if (used + 1 >= value_size) return false;
        value[used++] = byte;
    }
    if (*position != '"') return false;
    value[used] = '\0';
    return true;
}

static bool add_unique_path(char paths[][PATH_MAX], size_t maximum, size_t *count, const char *path) {
    if (!path || !*path || *count >= maximum) return false;
    char canonical[PATH_MAX];
    const char *stored = realpath(path, canonical) ? canonical : path;
    if (strlen(stored) >= PATH_MAX) return false;
    for (size_t i = 0; i < *count; ++i)
        if (strcmp(paths[i], stored) == 0) return true;
    memcpy(paths[*count], stored, strlen(stored) + 1);
    ++*count;
    return true;
}

static bool find_steam_game(char game_path[PATH_MAX], char *error, size_t error_size) {
    char libraries[MAX_STEAM_LIBRARIES][PATH_MAX];
    char candidates[MAX_STEAM_CANDIDATES][PATH_MAX];
    size_t library_count = 0, candidate_count = 0;
    const char *home = getenv("HOME");
    if (!home || !*home) {
        snprintf(error, error_size, "HOME is not set; pass the full path to RCT.EXE");
        return false;
    }
    char path[PATH_MAX];
    static const char *home_suffixes[] = {
        ".steam/steam", ".steam/root", ".steam/debian-installation", ".local/share/Steam"
    };
    for (size_t i = 0; i < sizeof(home_suffixes) / sizeof(home_suffixes[0]); ++i) {
        if (snprintf(path, sizeof(path), "%s/%s", home, home_suffixes[i]) < (int)sizeof(path))
            (void)add_unique_path(libraries, MAX_STEAM_LIBRARIES, &library_count, path);
    }
    const char *xdg_data_home = getenv("XDG_DATA_HOME");
    if (xdg_data_home && *xdg_data_home &&
        snprintf(path, sizeof(path), "%s/Steam", xdg_data_home) < (int)sizeof(path))
        (void)add_unique_path(libraries, MAX_STEAM_LIBRARIES, &library_count, path);

    for (size_t i = 0; i < library_count; ++i) {
        char folders_path[PATH_MAX];
        if (snprintf(folders_path, sizeof(folders_path), "%s/steamapps/libraryfolders.vdf", libraries[i]) >=
            (int)sizeof(folders_path)) continue;
        FILE *folders = fopen(folders_path, "r");
        if (!folders) continue;
        char line[2048], library_path[PATH_MAX];
        while (fgets(line, sizeof(line), folders)) {
            if (parse_vdf_value(line, "path", library_path, sizeof(library_path)))
                (void)add_unique_path(libraries, MAX_STEAM_LIBRARIES, &library_count, library_path);
        }
        fclose(folders);
    }

    for (size_t i = 0; i < library_count; ++i) {
        char manifest_path[PATH_MAX], install_directory[PATH_MAX];
        if (snprintf(manifest_path, sizeof(manifest_path), "%s/steamapps/appmanifest_285310.acf", libraries[i]) >=
            (int)sizeof(manifest_path)) continue;
        FILE *manifest = fopen(manifest_path, "r");
        if (!manifest) continue;
        bool found_directory = false;
        char line[2048];
        while (fgets(line, sizeof(line), manifest)) {
            if (parse_vdf_value(line, "installdir", install_directory, sizeof(install_directory))) {
                found_directory = true;
                break;
            }
        }
        fclose(manifest);
        if (!found_directory || !*install_directory || strchr(install_directory, '/') ||
            strcmp(install_directory, ".") == 0 || strcmp(install_directory, "..") == 0)
            continue;
        char executable[PATH_MAX], canonical[PATH_MAX];
        if (snprintf(executable, sizeof(executable), "%s/steamapps/common/%s/RCT.EXE",
                     libraries[i], install_directory) >= (int)sizeof(executable) ||
            !realpath(executable, canonical))
            continue;
        (void)add_unique_path(candidates, MAX_STEAM_CANDIDATES, &candidate_count, canonical);
    }

    if (candidate_count == 1) {
        memcpy(game_path, candidates[0], strlen(candidates[0]) + 1);
        return true;
    }
    if (candidate_count == 0) {
        snprintf(error, error_size,
                 "Steam App 285310 was not found in the standard Steam libraries; pass the full path to RCT.EXE");
        return false;
    }
    snprintf(error, error_size,
             "found multiple Steam installs for App 285310 (including '%.*s' and '%.*s'); pass the intended RCT.EXE path",
             140, candidates[0], 140, candidates[1]);
    return false;
}

static bool find_game_argument(char *const command[], char game_path[PATH_MAX], char *error, size_t error_size) {
    for (size_t i = 0; command[i]; ++i) {
        const char *arg = command[i];
        const char *base = strrchr(arg, '/');
        base = base ? base + 1 : arg;
        if (strcasecmp(base, "RCT.EXE") != 0) continue;
        if (validate_supported_game(arg, game_path, error, error_size)) return true;
        return false;
    }
    snprintf(error, error_size,
             "the Steam command did not expose RCT.EXE. Keep '%s run -- %%command%%' in Steam Launch Options.", APP_NAME);
    return false;
}

static bool encode_maps_path(const char *path, char output[PATH_MAX * 4]) {
    size_t used = 0;
    for (const unsigned char *p = (const unsigned char *)path; *p; ++p) {
        /* Linux procfs leaves spaces literal and escapes embedded newlines. */
        const char *escape = *p == '\n' ? "\\012" : NULL;
        if (escape) {
            size_t n = strlen(escape);
            if (used + n + 1 >= PATH_MAX * 4) return false;
            memcpy(output + used, escape, n);
            used += n;
        } else {
            if (used + 2 >= PATH_MAX * 4) return false;
            output[used++] = (char)*p;
        }
    }
    output[used] = '\0';
    return true;
}

static bool map_path_matches(const char *mapped, const char *expected) {
    size_t n = strlen(expected);
    return strncmp(mapped, expected, n) == 0 &&
           (mapped[n] == '\0' || strcmp(mapped + n, " (deleted)") == 0);
}

static bool find_module_base(pid_t pid, const char *escaped_path, uint64_t *base) {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%ld/maps", (long)pid);
    FILE *file = fopen(maps_path, "r");
    if (!file) return false;
    char line[8192];
    bool found = false;
    while (fgets(line, sizeof(line), file)) {
        unsigned long long start, end, offset;
        unsigned major, minor;
        unsigned long inode;
        char permissions[5];
        int consumed = 0;
        int fields = sscanf(line, "%llx-%llx %4s %llx %x:%x %lu %n",
                            &start, &end, permissions, &offset, &major, &minor, &inode, &consumed);
        (void)end; (void)major; (void)minor; (void)inode;
        if (fields != 7 || consumed <= 0 || offset != 0) continue;
        char *mapped = line + consumed;
        mapped[strcspn(mapped, "\r\n")] = '\0';
        if (map_path_matches(mapped, escaped_path)) {
            *base = (uint64_t)start;
            found = true;
            break;
        }
    }
    fclose(file);
    return found;
}

static bool process_read(int fd, uint64_t address, void *buffer, size_t size) {
    ssize_t got = pread(fd, buffer, size, (off_t)address);
    return got == (ssize_t)size;
}

static bool process_write(int fd, uint64_t address, const void *buffer, size_t size) {
    ssize_t wrote = pwrite(fd, buffer, size, (off_t)address);
    return wrote == (ssize_t)size;
}

static bool signature_bytes_match(const uint8_t *actual, const uint8_t *base_signature, size_t signature_size,
                                  const ImmediatePatch *patches, size_t patch_count,
                                  char *error, size_t error_size) {
    bool variable[64] = { false };
    if (signature_size > sizeof(variable)) {
        snprintf(error, error_size, "internal signature is too large");
        return false;
    }
    for (size_t i = 0; i < patch_count; ++i) {
        uint32_t offset = patches[i].address - 0x0057f95du;
        if (offset + 4 > signature_size) {
            snprintf(error, error_size, "internal resize signature offsets are invalid");
            return false;
        }
        for (unsigned j = 0; j < 4; ++j) variable[offset + j] = true;
        uint32_t value = read_le32(actual + offset);
        if (value != patches[i].old_value && value != patches[i].new_value) {
            /* The packed executable can expose zeroed immediates while it is still unpacking. */
            return false;
        }
    }
    for (size_t i = 0; i < signature_size; ++i) {
        if (!variable[i] && actual[i] != base_signature[i]) return false;
    }
    return true;
}

static PatchResult patch_process(pid_t pid, uint64_t base, uint32_t width, uint32_t height,
                                 char *message, size_t message_size) {
    const uint32_t resize_va = 0x0057f95du;
    const uint32_t stride_va = 0x0042420fu;
    const uint32_t stride_patch_va = 0x00424222u;
    ImmediatePatch patches[] = {
        { 0x0057f96au, 1280u, width },
        { 0x0057f973u, 1280u, width },
        { 0x0057f97au, 1024u, height },
        { 0x0057f983u, 1024u, height }
    };
    uint8_t resize_bytes[sizeof(resize_signature)];
    uint8_t stride_bytes[sizeof(stride_signature)];
    int memfd;
    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%ld/mem", (long)pid);
    memfd = open(mem_path, O_RDWR | O_CLOEXEC);
    if (memfd < 0) {
        if (errno == ENOENT || errno == ESRCH) return PATCH_PENDING;
        snprintf(message, message_size,
                 "cannot access process memory for PID %ld: %s. Launch through Steam as the same user and check ptrace restrictions.",
                 (long)pid, strerror(errno));
        return PATCH_FATAL;
    }
    if (!process_read(memfd, base + (resize_va - PE_IMAGE_BASE), resize_bytes, sizeof(resize_bytes)) ||
        !process_read(memfd, base + (stride_va - PE_IMAGE_BASE), stride_bytes, sizeof(stride_bytes))) {
        close(memfd);
        return PATCH_PENDING;
    }
    char signature_error[160] = {0};
    if (!signature_bytes_match(resize_bytes, resize_signature, sizeof(resize_signature),
                               patches, sizeof(patches) / sizeof(patches[0]),
                               signature_error, sizeof(signature_error))) {
        close(memfd);
        if (signature_error[0]) {
            snprintf(message, message_size, "%s", signature_error);
            return PATCH_FATAL;
        }
        return PATCH_PENDING;
    }

    uint8_t patched_stride_signature[sizeof(stride_signature)];
    memcpy(patched_stride_signature, stride_signature, sizeof(stride_signature));
    size_t code_offset = (size_t)(stride_patch_va - stride_va);
    memcpy(patched_stride_signature + code_offset, stride_patch, sizeof(stride_patch));
    bool code_is_original = memcmp(stride_bytes, stride_signature, sizeof(stride_signature)) == 0;
    bool code_is_patched = memcmp(stride_bytes, patched_stride_signature, sizeof(stride_signature)) == 0;
    if (!code_is_original && !code_is_patched) {
        close(memfd);
        snprintf(message, message_size, "the supported game mapped, but its tile-stride code did not match the known signature");
        return PATCH_FATAL;
    }

    bool all_caps_patched = true;
    for (size_t i = 0; i < sizeof(patches) / sizeof(patches[0]); ++i) {
        uint8_t bytes[4];
        if (!process_read(memfd, base + (patches[i].address - PE_IMAGE_BASE), bytes, sizeof(bytes))) {
            close(memfd);
            return PATCH_PENDING;
        }
        uint32_t value = read_le32(bytes);
        if (value != patches[i].old_value && value != patches[i].new_value) {
            close(memfd);
            snprintf(message, message_size, "unexpected live display limit %u at image offset 0x%x",
                     value, patches[i].address);
            return PATCH_FATAL;
        }
        if (value != patches[i].new_value) all_caps_patched = false;
    }
    if (all_caps_patched && code_is_patched) {
        close(memfd);
        snprintf(message, message_size, "already patched");
        return PATCH_SUCCESS;
    }

    if (!code_is_patched &&
        !process_write(memfd, base + (stride_patch_va - PE_IMAGE_BASE), stride_patch, sizeof(stride_patch))) {
        int saved_errno = errno;
        close(memfd);
        snprintf(message, message_size, "could not write the tile-stride patch: %s", strerror(saved_errno));
        return PATCH_FATAL;
    }
    for (size_t i = 0; i < sizeof(patches) / sizeof(patches[0]); ++i) {
        uint8_t bytes[4];
        write_le32(bytes, patches[i].new_value);
        if (!process_write(memfd, base + (patches[i].address - PE_IMAGE_BASE), bytes, sizeof(bytes))) {
            int saved_errno = errno;
            close(memfd);
            snprintf(message, message_size, "could not set live display limit at 0x%x: %s",
                     patches[i].address, strerror(saved_errno));
            return PATCH_FATAL;
        }
    }

    uint8_t verify_stride[sizeof(stride_patch)];
    if (!process_read(memfd, base + (stride_patch_va - PE_IMAGE_BASE), verify_stride, sizeof(verify_stride)) ||
        memcmp(verify_stride, stride_patch, sizeof(stride_patch)) != 0) {
        close(memfd);
        snprintf(message, message_size, "tile-stride patch read-back verification failed");
        return PATCH_FATAL;
    }
    for (size_t i = 0; i < sizeof(patches) / sizeof(patches[0]); ++i) {
        uint8_t bytes[4];
        if (!process_read(memfd, base + (patches[i].address - PE_IMAGE_BASE), bytes, sizeof(bytes)) ||
            read_le32(bytes) != patches[i].new_value) {
            close(memfd);
            snprintf(message, message_size, "display-limit read-back verification failed at 0x%x", patches[i].address);
            return PATCH_FATAL;
        }
    }
    close(memfd);
    snprintf(message, message_size, "patched live GDI size limits to %ux%u and rounded tile stride up", width, height);
    return PATCH_SUCCESS;
}

static bool find_game_pid(const char *game_path, uint32_t width, uint32_t height,
                          pid_t *pid_out, char *message, size_t message_size, bool *fatal) {
    char escaped_path[PATH_MAX * 4];
    if (!encode_maps_path(game_path, escaped_path)) {
        snprintf(message, message_size, "game path is too long for /proc map matching");
        *fatal = true;
        return false;
    }
    DIR *proc = opendir("/proc");
    if (!proc) {
        snprintf(message, message_size, "cannot scan /proc: %s", strerror(errno));
        *fatal = true;
        return false;
    }
    struct dirent *entry;
    bool fatal_seen = false;
    char first_error[256] = {0};
    while ((entry = readdir(proc))) {
        if (!isdigit((unsigned char)entry->d_name[0])) continue;
        char *end = NULL;
        long value = strtol(entry->d_name, &end, 10);
        if (!end || *end || value <= 0 || value > INT_MAX) continue;
        pid_t pid = (pid_t)value;
        uint64_t base;
        if (!find_module_base(pid, escaped_path, &base)) continue;
        char current_message[256] = {0};
        PatchResult result = patch_process(pid, base, width, height, current_message, sizeof(current_message));
        if (result == PATCH_SUCCESS) {
            *pid_out = pid;
            snprintf(message, message_size, "%s", current_message);
            closedir(proc);
            *fatal = false;
            return true;
        }
        if (result == PATCH_FATAL && !fatal_seen) {
            fatal_seen = true;
            snprintf(first_error, sizeof(first_error), "%s", current_message);
        }
    }
    closedir(proc);
    if (fatal_seen) {
        snprintf(message, message_size, "%s", first_error);
        *fatal = true;
    } else {
        *fatal = false;
    }
    return false;
}

static void sleep_poll_interval(void) {
    struct timespec delay = { .tv_sec = 0, .tv_nsec = POLL_INTERVAL_NS };
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {}
}

static int game_exit_code(int status) {
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 1;
}

static int run_game(const char *game_path, char *const game_command[], uint32_t output_width,
                    uint32_t output_height, unsigned refresh, int display_index) {
    if (!command_exists("gamescope")) {
        fprintf(stderr, "%s: Gamescope was not found in PATH. Install Gamescope, then retry.\n", APP_NAME);
        return 1;
    }
    uint32_t scale = (output_width >= 2560 && output_height >= 1080 &&
                      output_width % 2 == 0 && output_height % 2 == 0) ? 2u : 1u;
    uint32_t game_width = output_width / scale;
    uint32_t game_height = output_height / scale;
    char error[512] = {0};
    if (!configure_game(game_path, true, error, sizeof(error))) {
        fprintf(stderr, "%s: %s\n", APP_NAME, error);
        return 1;
    }

    char game_width_text[16], game_height_text[16], output_width_text[16], output_height_text[16];
    char refresh_text[16], display_index_text[16];
    snprintf(game_width_text, sizeof(game_width_text), "%u", game_width);
    snprintf(game_height_text, sizeof(game_height_text), "%u", game_height);
    snprintf(output_width_text, sizeof(output_width_text), "%u", output_width);
    snprintf(output_height_text, sizeof(output_height_text), "%u", output_height);
    snprintf(refresh_text, sizeof(refresh_text), "%u", refresh);
    snprintf(display_index_text, sizeof(display_index_text), "%d", display_index);

    size_t command_count = 0;
    while (game_command[command_count]) ++command_count;
    size_t fixed_count = 22u + (refresh ? 2u : 0u) + (display_index >= 0 ? 2u : 0u);
    char **args = calloc(fixed_count + command_count + 1, sizeof(char *));
    if (!args) {
        fprintf(stderr, "%s: out of memory building Gamescope command.\n", APP_NAME);
        return 1;
    }
    size_t n = 0;
    args[n++] = (char *)"gamescope";
    args[n++] = (char *)"-w"; args[n++] = game_width_text;
    args[n++] = (char *)"-h"; args[n++] = game_height_text;
    args[n++] = (char *)"-W"; args[n++] = output_width_text;
    args[n++] = (char *)"-H"; args[n++] = output_height_text;
    args[n++] = (char *)"-S"; args[n++] = (char *)"integer";
    args[n++] = (char *)"-F"; args[n++] = (char *)"nearest";
    if (refresh) { args[n++] = (char *)"-r"; args[n++] = refresh_text; }
    if (display_index >= 0) {
        args[n++] = (char *)"--display-index";
        args[n++] = display_index_text;
    }
    args[n++] = (char *)"-f";
    args[n++] = (char *)"--force-grab-cursor";
    args[n++] = (char *)"--force-windows-fullscreen";
    args[n++] = (char *)"--";
    for (size_t i = 0; i < command_count; ++i) args[n++] = game_command[i];
    args[n] = NULL;

    printf("Starting %ux%u inside Gamescope at %ux%u output (%ux integer scale)",
           game_width, game_height, output_width, output_height, scale);
    if (display_index >= 0) printf(" on display index %d", display_index);
    putchar('.');
    putchar('\n');
    fflush(stdout);
    pid_t child = fork();
    if (child < 0) {
        fprintf(stderr, "%s: cannot start Gamescope: %s\n", APP_NAME, strerror(errno));
        free(args);
        return 1;
    }
    if (child == 0) {
        execvp("gamescope", args);
        fprintf(stderr, "%s: cannot execute Gamescope: %s\n", APP_NAME, strerror(errno));
        _exit(127);
    }
    free(args);

    time_t deadline = time(NULL) + PATCH_TIMEOUT_SECONDS;
    bool announced = false;
    while (time(NULL) < deadline) {
        int status = 0;
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) {
            fprintf(stderr, "%s: game command exited before its runtime patch could be confirmed.\n", APP_NAME);
            int child_code = game_exit_code(status);
            return child_code == 0 ? 1 : child_code;
        }
        if (waited < 0 && errno != EINTR) {
            fprintf(stderr, "%s: could not monitor Gamescope: %s\n", APP_NAME, strerror(errno));
            return 1;
        }
        pid_t game_pid = 0;
        char patch_message[256] = {0};
        bool fatal = false;
        if (find_game_pid(game_path, game_width, game_height, &game_pid,
                          patch_message, sizeof(patch_message), &fatal)) {
            printf("RCT.EXE PID %ld: %s.\n", (long)game_pid, patch_message);
            fflush(stdout);
            int status_after_patch = 0;
            while (waitpid(child, &status_after_patch, 0) < 0) {
                if (errno == EINTR) continue;
                fprintf(stderr, "%s: wait for Gamescope failed: %s\n", APP_NAME, strerror(errno));
                return 1;
            }
            return game_exit_code(status_after_patch);
        }
        if (fatal) {
            fprintf(stderr, "%s: refusing to modify game memory: %s\n", APP_NAME, patch_message);
            kill(child, SIGTERM);
            while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
            return 1;
        }
        if (!announced) {
            printf("Waiting for the supported RCT.EXE to unpack its renderer...\n");
            fflush(stdout);
            announced = true;
        }
        sleep_poll_interval();
    }
    fprintf(stderr, "%s: timed out after %u seconds before a supported renderer was found; stopping Gamescope.\n",
            APP_NAME, PATCH_TIMEOUT_SECONDS);
    kill(child, SIGTERM);
    while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
    return 1;
}

static void print_usage(FILE *stream, const char *program) {
    fprintf(stream,
        "%s %s — guarded Linux launcher patch for RollerCoaster Tycoon Deluxe\n\n"
        "Usage:\n"
        "  %s doctor <path/to/RCT.EXE>\n"
        "  %s displays\n"
        "  %s install [path/to/RCT.EXE] [--launcher <path>] [--prefix <existing-prefix>]\n"
        "  %s uninstall [path/to/RCT.EXE]\n"
        "  %s configure <path/to/RCT.EXE> [--launcher <path/to/rct-ultrawide>]\n"
        "  %s restore <path/to/RCT.EXE>\n"
        "  %s run [--monitor INDEX] [--output WIDTHxHEIGHT] [--refresh HZ] -- <Steam %%command%%>\n"
        "  %s --version\n\n"
        "Steam Launch Options:\n"
        "  \"/path/to/rct-ultrawide\" run -- %%command%%\n\n"
        "Only the listed RCT Deluxe executable build is supported. The original EXE is never modified.\n",
        APP_NAME, APP_VERSION, program, program, program, program, program, program, program, program);
}

static int command_doctor(const char *input_path) {
    char game_path[PATH_MAX], error[512] = {0};
    if (!validate_supported_game(input_path, game_path, error, sizeof(error))) {
        fprintf(stderr, "%s: %s\n", APP_NAME, error);
        return 1;
    }
    char config_path[PATH_MAX], backup_path[PATH_MAX];
    if (!derive_config_paths(game_path, config_path, backup_path)) {
        fprintf(stderr, "%s: cannot build Game.cfg path.\n", APP_NAME);
        return 1;
    }
    uint8_t config[CONFIG_SIZE];
    mode_t mode;
    if (!read_config(config_path, config, &mode, error, sizeof(error))) {
        fprintf(stderr, "%s: %s\n", APP_NAME, error);
        return 1;
    }
    (void)mode;
    printf("Supported RCT Deluxe build: SHA-256 %s\n", SUPPORTED_SHA256);
    printf("Executable: %s\n", game_path);
    printf("Game.cfg: %s (windowed flag: %u)\n", config_path, config[CONFIG_DISPLAY_MODE_OFFSET]);
    struct stat st;
    if (lstat(backup_path, &st) == 0) {
        uint8_t backup[CONFIG_SIZE];
        char backup_error[256] = {0};
        if (S_ISREG(st.st_mode) && read_config(backup_path, backup, NULL, backup_error, sizeof(backup_error)))
            printf("Backup: valid (%s; backed-up display-mode flag %u)\n", backup_path,
                   backup[CONFIG_DISPLAY_MODE_OFFSET]);
        else
            printf("Backup: invalid or unreadable (%s%s%s)\n", backup_path,
                   backup_error[0] ? ": " : "", backup_error);
    } else {
        printf("Backup: not created yet\n");
    }
    DisplayInfo displays[MAX_DISPLAYS];
    size_t display_count;
    char display_error[256] = {0};
    if (query_displays(displays, &display_count, display_error, sizeof(display_error))) {
        printf("Active XRandR displays (default: index %zu):\n", primary_display_index(displays, display_count));
        print_displays(stdout, displays, display_count);
    } else {
        printf("Display detection: unavailable (%s); run accepts --output WIDTHxHEIGHT\n", display_error);
    }
    if (command_exists("gamescope")) printf("Gamescope: available\n");
    else printf("Gamescope: not found in PATH\n");
    if (getenv("DISPLAY") && *getenv("DISPLAY"))
        printf("X11 DISPLAY: %s\n", getenv("DISPLAY"));
    else
        printf("X11 DISPLAY: not set\n");
    if (getenv("STEAM_COMPAT_DATA_PATH") && *getenv("STEAM_COMPAT_DATA_PATH"))
        printf("Steam Proton prefix: available in this process environment\n");
    else
        printf("Steam Proton prefix: not set (normal when doctor is run outside Steam)\n");
    return 0;
}

static int command_configure(const char *input_path, const char *launcher_path) {
    char game_path[PATH_MAX], error[512] = {0};
    if (!validate_supported_game(input_path, game_path, error, sizeof(error))) {
        fprintf(stderr, "%s: %s\n", APP_NAME, error);
        return 1;
    }
    char quoted[PATH_MAX * 4];
    if (launcher_path) {
        char resolved[PATH_MAX];
        if (!realpath(launcher_path, resolved)) {
            fprintf(stderr, "%s: cannot resolve launcher '%s': %s\n", APP_NAME, launcher_path, strerror(errno));
            return 1;
        }
        struct stat launcher_stat;
        if (stat(resolved, &launcher_stat) != 0 || !S_ISREG(launcher_stat.st_mode) || access(resolved, X_OK) != 0) {
            fprintf(stderr, "%s: launcher '%s' is not a regular executable file.\n", APP_NAME, resolved);
            return 1;
        }
        if (!shell_quote(resolved, quoted)) {
            fprintf(stderr, "%s: launcher path is too long to quote.\n", APP_NAME);
            return 1;
        }
    } else {
        strcpy(quoted, "\"/absolute/path/to/rct-ultrawide\"");
    }
    if (!configure_game(game_path, true, error, sizeof(error))) {
        fprintf(stderr, "%s: %s\n", APP_NAME, error);
        return 1;
    }
    if (launcher_path) {
        printf("Steam Launch Options:\n%s run -- %%command%%\n", quoted);
    } else {
        printf("Set this in Steam > Properties > Launch Options:\n\"/absolute/path/to/rct-ultrawide\" run -- %%command%%\n");
    }
    return 0;
}

static int command_install(int argc, char **argv) {
    const char *input_path = NULL, *launcher_path = NULL, *prefix = NULL;
    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "--launcher") == 0 && i + 1 < argc) {
            launcher_path = argv[++i];
        } else if (strcmp(argv[i], "--prefix") == 0 && i + 1 < argc) {
            prefix = argv[++i];
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "%s: unknown install option '%s'.\n", APP_NAME, argv[i]);
            return 2;
        } else if (!input_path) {
            input_path = argv[i];
        } else {
            fprintf(stderr, "%s: install accepts one RCT.EXE path.\n", APP_NAME);
            return 2;
        }
    }
    if (prefix && (strchr(prefix, '\n') || strchr(prefix, '\r') || strstr(prefix, "%command%"))) {
        fprintf(stderr, "%s: --prefix must be one line of existing Steam prefixes and must omit %%command%%.\n",
                APP_NAME);
        return 2;
    }
    char discovered_path[PATH_MAX];
    if (!input_path) {
        char find_error[512] = {0};
        if (!find_steam_game(discovered_path, find_error, sizeof(find_error))) {
            fprintf(stderr, "%s: %s\n", APP_NAME, find_error);
            return 1;
        }
        input_path = discovered_path;
        printf("Found Steam App 285310 at %s\n", input_path);
    }
    char game_path[PATH_MAX], error[512] = {0};
    if (!validate_supported_game(input_path, game_path, error, sizeof(error))) {
        fprintf(stderr, "%s: %s\n", APP_NAME, error);
        return 1;
    }
    char quoted_launcher[PATH_MAX * 4];
    if (launcher_path) {
        char resolved[PATH_MAX];
        struct stat launcher_stat;
        if (!realpath(launcher_path, resolved)) {
            fprintf(stderr, "%s: launcher '%s' is missing or not executable: %s\n",
                    APP_NAME, launcher_path, strerror(errno));
            return 1;
        }
        if (stat(resolved, &launcher_stat) != 0) {
            fprintf(stderr, "%s: cannot inspect launcher '%s': %s\n", APP_NAME, resolved, strerror(errno));
            return 1;
        }
        if (!S_ISREG(launcher_stat.st_mode) || access(resolved, X_OK) != 0) {
            fprintf(stderr, "%s: launcher '%s' is not a regular executable file.\n", APP_NAME, resolved);
            return 1;
        }
        if (!shell_quote(resolved, quoted_launcher)) {
            fprintf(stderr, "%s: launcher path is too long to quote.\n", APP_NAME);
            return 1;
        }
    } else {
        strcpy(quoted_launcher, "\"/absolute/path/to/rct-ultrawide\"");
    }
    if (!configure_game(game_path, true, error, sizeof(error))) {
        fprintf(stderr, "%s: %s\n", APP_NAME, error);
        return 1;
    }
    printf("\nPaste this into Steam > RollerCoaster Tycoon Deluxe > Properties > Launch Options:\n");
    if (prefix && *prefix) printf("%s ", prefix);
    printf("%s run -- %%command%%\n", quoted_launcher);
    printf("Steam settings were not edited. Keep any existing environment or performance prefix before the command above.\n");
    return 0;
}

static int command_uninstall(int argc, char **argv) {
    if (argc > 3) { print_usage(stderr, argv[0]); return 2; }
    char discovered_path[PATH_MAX];
    const char *input_path = argc == 3 ? argv[2] : NULL;
    if (!input_path) {
        char find_error[512] = {0};
        if (!find_steam_game(discovered_path, find_error, sizeof(find_error))) {
            fprintf(stderr, "%s: %s\n", APP_NAME, find_error);
            return 1;
        }
        input_path = discovered_path;
        printf("Found Steam App 285310 at %s\n", input_path);
    }
    char game_path[PATH_MAX], error[512] = {0};
    if (!validate_supported_game(input_path, game_path, error, sizeof(error))) {
        fprintf(stderr, "%s: %s\n", APP_NAME, error);
        return 1;
    }
    if (!restore_game_config(game_path, error, sizeof(error))) {
        fprintf(stderr, "%s: %s\n", APP_NAME, error);
        return 1;
    }
    printf("Remove only the rct-ultrawide command from Steam Launch Options; keep any prefixes that were already there.\n");
    return 0;
}

static int command_displays(void) {
    DisplayInfo displays[MAX_DISPLAYS];
    size_t display_count;
    char error[256] = {0};
    if (!query_displays(displays, &display_count, error, sizeof(error))) {
        fprintf(stderr, "%s: %s\n", APP_NAME, error);
        return 1;
    }
    printf("Active displays (use the index with run --monitor INDEX):\n");
    print_displays(stdout, displays, display_count);
    return 0;
}

static bool parse_monitor_index(const char *text, int *index) {
    if (!text || !*text || text[0] == '-') return false;
    errno = 0;
    char *end = NULL;
    unsigned long value = strtoul(text, &end, 10);
    if (errno || !end || *end || value >= MAX_DISPLAYS) return false;
    *index = (int)value;
    return true;
}

static int command_run(int argc, char **argv) {
    uint32_t output_width = 0, output_height = 0;
    unsigned refresh = 0;
    bool output_supplied = false;
    int display_index = -1;
    int separator = -1;
    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "--") == 0) { separator = i; break; }
        if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            if (!parse_dimensions(argv[++i], &output_width, &output_height)) {
                fprintf(stderr, "%s: invalid output size; use WIDTHxHEIGHT, such as 3440x1440.\n", APP_NAME);
                return 2;
            }
            output_supplied = true;
        } else if ((strcmp(argv[i], "--monitor") == 0 || strcmp(argv[i], "--display-index") == 0) &&
                   i + 1 < argc) {
            if (!parse_monitor_index(argv[++i], &display_index)) {
                fprintf(stderr, "%s: monitor index must be a number from 0 to %u.\n",
                        APP_NAME, MAX_DISPLAYS - 1);
                return 2;
            }
        } else if (strcmp(argv[i], "--refresh") == 0 && i + 1 < argc) {
            char *end = NULL;
            unsigned long value = strtoul(argv[++i], &end, 10);
            if (!end || *end || value < 30 || value > 360) {
                fprintf(stderr, "%s: refresh rate must be 30–360 Hz.\n", APP_NAME);
                return 2;
            }
            refresh = (unsigned)value;
        } else {
            fprintf(stderr, "%s: unknown run option '%s'.\n", APP_NAME, argv[i]);
            return 2;
        }
    }
    if (separator < 0 || separator + 1 >= argc) {
        fprintf(stderr, "%s: run needs '-- <Steam %%command%%>'.\n", APP_NAME);
        return 2;
    }
    char game_path[PATH_MAX], error[512] = {0};
    char **game_command = &argv[separator + 1];
    if (!find_game_argument(game_command, game_path, error, sizeof(error))) {
        fprintf(stderr, "%s: %s\n", APP_NAME, error);
        return 1;
    }
    if (!output_supplied || display_index >= 0) {
        DisplayInfo displays[MAX_DISPLAYS];
        size_t display_count;
        char display_error[256] = {0};
        if (!query_displays(displays, &display_count, display_error, sizeof(display_error))) {
            fprintf(stderr, "%s: %s; pass --output WIDTHxHEIGHT and avoid --monitor if no XRandR output is available.\n",
                    APP_NAME, display_error);
            return 1;
        }
        size_t selected = display_index >= 0 ? (size_t)display_index : primary_display_index(displays, display_count);
        if (selected >= display_count) {
            fprintf(stderr, "%s: monitor index %zu is not active; available displays are:\n", APP_NAME, selected);
            print_displays(stderr, displays, display_count);
            return 2;
        }
        if (!output_supplied) {
            output_width = displays[selected].width;
            output_height = displays[selected].height;
        }
        if (display_index < 0) display_index = (int)selected;
    }
    if (output_width < 320 || output_height < 200 || output_width > 32767 || output_height > 32767) {
        fprintf(stderr, "%s: output dimensions are outside the supported range.\n", APP_NAME);
        return 2;
    }
    return run_game(game_path, game_command, output_width, output_height, refresh, display_index);
}

int main(int argc, char **argv) {
    if (sizeof(void *) != 8) {
        fprintf(stderr, "%s: this build requires a 64-bit Linux process.\n", APP_NAME);
        return 1;
    }
    if (argc < 2 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "help") == 0) {
        print_usage(argc < 2 ? stderr : stdout, argv[0]);
        return argc < 2 ? 2 : 0;
    }
    if (strcmp(argv[1], "--version") == 0) {
        printf("%s %s\nSupported RCT.EXE SHA-256: %s\n", APP_NAME, APP_VERSION, SUPPORTED_SHA256);
        return 0;
    }
    if (strcmp(argv[1], "doctor") == 0) {
        if (argc != 3) { print_usage(stderr, argv[0]); return 2; }
        return command_doctor(argv[2]);
    }
    if (strcmp(argv[1], "displays") == 0) {
        if (argc != 2) { print_usage(stderr, argv[0]); return 2; }
        return command_displays();
    }
    if (strcmp(argv[1], "install") == 0) return command_install(argc, argv);
    if (strcmp(argv[1], "uninstall") == 0) return command_uninstall(argc, argv);
    if (strcmp(argv[1], "configure") == 0) {
        const char *launcher = NULL;
        if (argc == 3) return command_configure(argv[2], NULL);
        if (argc == 5 && strcmp(argv[3], "--launcher") == 0) launcher = argv[4];
        else { print_usage(stderr, argv[0]); return 2; }
        return command_configure(argv[2], launcher);
    }
    if (strcmp(argv[1], "restore") == 0) {
        if (argc != 3) { print_usage(stderr, argv[0]); return 2; }
        char game_path[PATH_MAX], error[512] = {0};
        if (!validate_supported_game(argv[2], game_path, error, sizeof(error))) {
            fprintf(stderr, "%s: %s\n", APP_NAME, error);
            return 1;
        }
        if (!restore_game_config(game_path, error, sizeof(error))) {
            fprintf(stderr, "%s: %s\n", APP_NAME, error);
            return 1;
        }
        return 0;
    }
    if (strcmp(argv[1], "run") == 0) return command_run(argc, argv);
    fprintf(stderr, "%s: unknown command '%s'.\n", APP_NAME, argv[1]);
    print_usage(stderr, argv[0]);
    return 2;
}
