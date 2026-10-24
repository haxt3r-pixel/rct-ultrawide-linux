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
#define APP_VERSION "0.1.0"
#define SUPPORTED_SHA256 "bdfebd64383b231de0252fe0726523d1c45aa2c4da919c2d7ed8bfb7aaa05c76"
#define PE_IMAGE_BASE 0x00400000u
#define CONFIG_SIZE 100u
#define CONFIG_DISPLAY_MODE_OFFSET 23u
#define PATCH_TIMEOUT_SECONDS 120
#define POLL_INTERVAL_NS 20000000L

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

static bool detect_output_size(uint32_t *width, uint32_t *height) {
    FILE *pipe = popen("xrandr --current 2>/dev/null", "r");
    if (!pipe) return false;
    char line[1024];
    bool found = false;
    while (fgets(line, sizeof(line), pipe)) {
        char *current = strstr(line, " current ");
        if (!current) continue;
        unsigned w, h;
        if (sscanf(current + 9, "%u x %u", &w, &h) == 2 && w >= 320 && h >= 200 && w <= 32767 && h <= 32767) {
            *width = w;
            *height = h;
            found = true;
            break;
        }
    }
    (void)pclose(pipe);
    return found;
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
                    uint32_t output_height, unsigned refresh) {
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

    char game_width_text[16], game_height_text[16], output_width_text[16], output_height_text[16], refresh_text[16];
    snprintf(game_width_text, sizeof(game_width_text), "%u", game_width);
    snprintf(game_height_text, sizeof(game_height_text), "%u", game_height);
    snprintf(output_width_text, sizeof(output_width_text), "%u", output_width);
    snprintf(output_height_text, sizeof(output_height_text), "%u", output_height);
    snprintf(refresh_text, sizeof(refresh_text), "%u", refresh);

    size_t command_count = 0;
    while (game_command[command_count]) ++command_count;
    size_t fixed_count = refresh ? 20u : 18u;
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
    args[n++] = (char *)"-f";
    args[n++] = (char *)"--force-grab-cursor";
    args[n++] = (char *)"--force-windows-fullscreen";
    args[n++] = (char *)"--";
    for (size_t i = 0; i < command_count; ++i) args[n++] = game_command[i];
    args[n] = NULL;

    printf("Starting %ux%u inside Gamescope at %ux%u output (%ux integer scale).\n",
           game_width, game_height, output_width, output_height, scale);
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
            return game_exit_code(status);
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
        "  %s configure <path/to/RCT.EXE> [--launcher <path/to/rct-ultrawide>]\n"
        "  %s restore <path/to/RCT.EXE>\n"
        "  %s run [--output WIDTHxHEIGHT] [--refresh HZ] -- <Steam %%command%%>\n"
        "  %s --version\n\n"
        "Steam Launch Options:\n"
        "  \"/path/to/rct-ultrawide\" run -- %%command%%\n\n"
        "Only the listed RCT Deluxe executable build is supported. The original EXE is never modified.\n",
        APP_NAME, APP_VERSION, program, program, program, program, program);
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
    if (lstat(backup_path, &st) == 0)
        printf("Backup: %s\n", backup_path);
    else
        printf("Backup: not created yet\n");
    uint32_t width, height;
    if (detect_output_size(&width, &height))
        printf("Detected X display: %ux%u\n", width, height);
    else
        printf("Detected X display: unavailable (run accepts --output WIDTHxHEIGHT)\n");
    if (command_exists("gamescope")) printf("Gamescope: available\n");
    else printf("Gamescope: not found in PATH\n");
    return 0;
}

static int command_configure(const char *input_path, const char *launcher_path) {
    char game_path[PATH_MAX], error[512] = {0};
    if (!validate_supported_game(input_path, game_path, error, sizeof(error))) {
        fprintf(stderr, "%s: %s\n", APP_NAME, error);
        return 1;
    }
    if (!configure_game(game_path, true, error, sizeof(error))) {
        fprintf(stderr, "%s: %s\n", APP_NAME, error);
        return 1;
    }
    if (launcher_path) {
        char resolved[PATH_MAX];
        if (!realpath(launcher_path, resolved)) {
            fprintf(stderr, "%s: cannot resolve launcher '%s': %s\n", APP_NAME, launcher_path, strerror(errno));
            return 1;
        }
        char quoted[PATH_MAX * 4];
        if (!shell_quote(resolved, quoted)) {
            fprintf(stderr, "%s: launcher path is too long to quote.\n", APP_NAME);
            return 1;
        }
        printf("Steam Launch Options:\n%s run -- %%command%%\n", quoted);
    } else {
        printf("Set this in Steam > Properties > Launch Options:\n\"/absolute/path/to/rct-ultrawide\" run -- %%command%%\n");
    }
    return 0;
}

static int command_run(int argc, char **argv) {
    uint32_t output_width = 0, output_height = 0;
    unsigned refresh = 0;
    int separator = -1;
    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "--") == 0) { separator = i; break; }
        if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            if (!parse_dimensions(argv[++i], &output_width, &output_height)) {
                fprintf(stderr, "%s: invalid output size; use WIDTHxHEIGHT, such as 3440x1440.\n", APP_NAME);
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
    if (output_width == 0 && !detect_output_size(&output_width, &output_height)) {
        fprintf(stderr, "%s: could not detect the active display with xrandr; pass --output WIDTHxHEIGHT.\n", APP_NAME);
        return 1;
    }
    if (output_width < 320 || output_height < 200 || output_width > 32767 || output_height > 32767) {
        fprintf(stderr, "%s: output dimensions are outside the supported range.\n", APP_NAME);
        return 2;
    }
    return run_game(game_path, game_command, output_width, output_height, refresh);
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
