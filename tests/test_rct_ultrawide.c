int rct_ultrawide_program_main(int argc, char **argv);
#define main rct_ultrawide_program_main
#include "../src/rct-ultrawide.c"
#undef main

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        exit(EXIT_FAILURE); \
    } \
} while (0)

static void join_path(char output[PATH_MAX], const char *parent, const char *child) {
    int length = snprintf(output, PATH_MAX, "%s/%s", parent, child);
    CHECK(length >= 0 && length < PATH_MAX);
}

static void make_directory(const char *path) {
    CHECK(mkdir(path, 0700) == 0);
}

static void write_test_file(const char *path, const void *bytes, size_t length, mode_t mode) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    CHECK(fd >= 0);
    CHECK(write_all(fd, bytes, length));
    CHECK(fchmod(fd, mode) == 0);
    CHECK(close(fd) == 0);
}

static size_t read_test_file(const char *path, char *buffer, size_t capacity) {
    CHECK(capacity > 0);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0);
    size_t used = 0;
    while (used + 1 < capacity) {
        ssize_t count = read(fd, buffer + used, capacity - used - 1);
        if (count < 0 && errno == EINTR) continue;
        CHECK(count >= 0);
        if (count == 0) break;
        used += (size_t)count;
    }
    char extra;
    CHECK(read(fd, &extra, 1) == 0);
    CHECK(close(fd) == 0);
    buffer[used] = '\0';
    return used;
}

static void remove_tree(const char *path) {
    struct stat st;
    CHECK(lstat(path, &st) == 0);
    if (!S_ISDIR(st.st_mode)) {
        CHECK(unlink(path) == 0);
        return;
    }
    DIR *directory = opendir(path);
    CHECK(directory != NULL);
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        char child[PATH_MAX];
        join_path(child, path, entry->d_name);
        remove_tree(child);
    }
    CHECK(closedir(directory) == 0);
    CHECK(rmdir(path) == 0);
}

static void create_game_fixture(const char *directory, char game_path[PATH_MAX],
                                char config_path[PATH_MAX], uint8_t initial[CONFIG_SIZE]) {
    make_directory(directory);
    join_path(game_path, directory, "RCT.EXE");
    static const char fixture_executable[] = "not a redistributable game executable";
    write_test_file(game_path, fixture_executable, sizeof(fixture_executable) - 1, 0700);
    char data_directory[PATH_MAX];
    join_path(data_directory, directory, "Data");
    make_directory(data_directory);
    join_path(config_path, data_directory, "Game.cfg");
    for (size_t i = 0; i < CONFIG_SIZE; ++i) initial[i] = (uint8_t)(i * 31u + 7u);
    initial[CONFIG_DISPLAY_MODE_OFFSET] = 1;
    write_test_file(config_path, initial, CONFIG_SIZE, 0600);
}

static void test_parsers(void) {
    uint32_t width = 0, height = 0;
    CHECK(parse_dimensions("3440x1440", &width, &height));
    CHECK(width == 3440 && height == 1440);
    CHECK(!parse_dimensions("3440x1440junk", &width, &height));
    CHECK(!parse_dimensions("319x200", &width, &height));

    int monitor = -1;
    CHECK(parse_monitor_index("0", &monitor) && monitor == 0);
    CHECK(parse_monitor_index("31", &monitor) && monitor == 31);
    CHECK(!parse_monitor_index("-1", &monitor));
    CHECK(!parse_monitor_index("32", &monitor));
    CHECK(!parse_monitor_index("1x", &monitor));

    long x = 0, y = 0;
    CHECK(parse_display_geometry("3440x1440+0+0", &width, &height, &x, &y));
    CHECK(width == 3440 && height == 1440 && x == 0 && y == 0);
    CHECK(parse_display_geometry("1920x1080-1920+32", &width, &height, &x, &y));
    CHECK(width == 1920 && height == 1080 && x == -1920 && y == 32);
    CHECK(!parse_display_geometry("disconnected", &width, &height, &x, &y));

    char value[PATH_MAX];
    CHECK(parse_vdf_value("    \"path\" \"/mnt/Steam Library\"", "path", value, sizeof(value)));
    CHECK(strcmp(value, "/mnt/Steam Library") == 0);
    CHECK(!parse_vdf_value("    \"somepath\" \"/tmp\"", "path", value, sizeof(value)));
}

static void test_unsupported_executable(const char *root) {
    char directory[PATH_MAX], path[PATH_MAX], resolved[PATH_MAX], error[512] = {0};
    join_path(directory, root, "unsupported");
    make_directory(directory);
    join_path(path, directory, "RCT.EXE");
    static const char bytes[] = "unsupported fixture";
    write_test_file(path, bytes, sizeof(bytes) - 1, 0600);
    CHECK(!validate_supported_game(path, resolved, error, sizeof(error)));
    CHECK(strstr(error, "unsupported RCT.EXE build") != NULL);
    CHECK(strstr(error, SUPPORTED_SHA256) != NULL);
}

static void test_config_backup_restore(const char *root) {
    char fixture_root[PATH_MAX], game_path[PATH_MAX], config_path[PATH_MAX];
    uint8_t original[CONFIG_SIZE], current[CONFIG_SIZE], backup[CONFIG_SIZE];
    join_path(fixture_root, root, "config-round-trip");
    create_game_fixture(fixture_root, game_path, config_path, original);

    char error[512] = {0};
    CHECK(configure_game(game_path, false, error, sizeof(error)));
    CHECK(read_config(config_path, current, NULL, error, sizeof(error)));
    CHECK(current[CONFIG_DISPLAY_MODE_OFFSET] == 0);
    for (size_t i = 0; i < CONFIG_SIZE; ++i) {
        if (i == CONFIG_DISPLAY_MODE_OFFSET) continue;
        CHECK(current[i] == original[i]);
    }

    char backup_path[PATH_MAX];
    join_path(backup_path, fixture_root, "Data/Game.cfg.rct-ultrawide.bak");
    CHECK(read_config(backup_path, backup, NULL, error, sizeof(error)));
    CHECK(memcmp(backup, original, CONFIG_SIZE) == 0);

    current[7] ^= 0x5au;
    write_test_file(config_path, current, CONFIG_SIZE, 0600);
    CHECK(configure_game(game_path, false, error, sizeof(error)));
    CHECK(read_config(backup_path, backup, NULL, error, sizeof(error)));
    CHECK(memcmp(backup, original, CONFIG_SIZE) == 0);
    CHECK(restore_game_config(game_path, error, sizeof(error)));
    CHECK(read_config(config_path, current, NULL, error, sizeof(error)));
    CHECK(current[CONFIG_DISPLAY_MODE_OFFSET] == original[CONFIG_DISPLAY_MODE_OFFSET]);
    CHECK(current[7] == (uint8_t)(original[7] ^ 0x5au));
    for (size_t i = 0; i < CONFIG_SIZE; ++i) {
        if (i == CONFIG_DISPLAY_MODE_OFFSET || i == 7) continue;
        CHECK(current[i] == original[i]);
    }

    char reject_root[PATH_MAX], reject_game[PATH_MAX], reject_config[PATH_MAX];
    uint8_t reject_original[CONFIG_SIZE], short_backup[CONFIG_SIZE - 1];
    memset(short_backup, 0, sizeof(short_backup));
    join_path(reject_root, root, "invalid-backup");
    create_game_fixture(reject_root, reject_game, reject_config, reject_original);
    join_path(backup_path, reject_root, "Data/Game.cfg.rct-ultrawide.bak");
    write_test_file(backup_path, short_backup, sizeof(short_backup), 0600);
    CHECK(!configure_game(reject_game, false, error, sizeof(error)));
    CHECK(read_config(reject_config, current, NULL, error, sizeof(error)));
    CHECK(memcmp(current, reject_original, CONFIG_SIZE) == 0);
}

static void create_steam_install(const char *library, const char *install_directory,
                                 char executable[PATH_MAX]) {
    char steamapps[PATH_MAX], common[PATH_MAX], game_directory[PATH_MAX];
    join_path(steamapps, library, "steamapps");
    make_directory(steamapps);
    join_path(common, steamapps, "common");
    make_directory(common);
    join_path(game_directory, common, install_directory);
    make_directory(game_directory);
    join_path(executable, game_directory, "RCT.EXE");
    static const char fixture_executable[] = "fixture";
    write_test_file(executable, fixture_executable, sizeof(fixture_executable) - 1, 0600);

    char manifest[PATH_MAX];
    join_path(manifest, library, "steamapps/appmanifest_285310.acf");
    char manifest_text[256];
    int length = snprintf(manifest_text, sizeof(manifest_text),
                          "\"AppState\"\n{\n  \"installdir\" \"%s\"\n}\n", install_directory);
    CHECK(length >= 0 && (size_t)length < sizeof(manifest_text));
    write_test_file(manifest, manifest_text, (size_t)length, 0600);
}

static void test_steam_library_discovery(const char *root) {
    char home[PATH_MAX], dot_steam[PATH_MAX], steam_directory[PATH_MAX], steamapps[PATH_MAX];
    char library_one[PATH_MAX], library_two[PATH_MAX], executable_one[PATH_MAX], executable_two[PATH_MAX];
    join_path(home, root, "steam-home");
    make_directory(home);
    join_path(dot_steam, home, ".steam");
    make_directory(dot_steam);
    join_path(steam_directory, dot_steam, "steam");
    make_directory(steam_directory);
    join_path(steamapps, steam_directory, "steamapps");
    make_directory(steamapps);
    join_path(library_one, root, "external Steam Library One");
    make_directory(library_one);
    join_path(library_two, root, "external Steam Library Two");
    make_directory(library_two);
    create_steam_install(library_one, "RollerCoaster Tycoon Deluxe", executable_one);
    create_steam_install(library_two, "RCT Deluxe Second Copy", executable_two);

    char folders_path[PATH_MAX], folders_text[PATH_MAX * 3], error[512] = {0}, found[PATH_MAX];
    join_path(folders_path, steamapps, "libraryfolders.vdf");
    int length = snprintf(folders_text, sizeof(folders_text),
                          "\"libraryfolders\"\n{\n  \"0\"\n  {\n    \"path\" \"%s\"\n  }\n}\n",
                          library_one);
    CHECK(length >= 0 && (size_t)length < sizeof(folders_text));
    write_test_file(folders_path, folders_text, (size_t)length, 0600);

    CHECK(setenv("HOME", home, 1) == 0);
    CHECK(unsetenv("XDG_DATA_HOME") == 0);
    CHECK(find_steam_game(found, error, sizeof(error)));
    CHECK(strcmp(found, executable_one) == 0);

    length = snprintf(folders_text, sizeof(folders_text),
                      "\"libraryfolders\"\n{\n  \"0\"\n  {\n    \"path\" \"%s\"\n  }\n  \"1\"\n  {\n    \"path\" \"%s\"\n  }\n}\n",
                      library_one, library_two);
    CHECK(length >= 0 && (size_t)length < sizeof(folders_text));
    write_test_file(folders_path, folders_text, (size_t)length, 0600);
    error[0] = '\0';
    CHECK(!find_steam_game(found, error, sizeof(error)));
    CHECK(strstr(error, "multiple Steam installs") != NULL);
}

static void test_displays_and_gamescope(const char *root) {
    char bin_directory[PATH_MAX], xrandr_path[PATH_MAX], gamescope_path[PATH_MAX];
    char args_path[PATH_MAX], fixture_root[PATH_MAX], game_path[PATH_MAX], config_path[PATH_MAX];
    join_path(bin_directory, root, "bin");
    make_directory(bin_directory);
    join_path(xrandr_path, bin_directory, "xrandr");
    static const char xrandr_script[] =
        "#!/bin/sh\n"
        "printf '%s\\n' 'Screen 0: minimum 320 x 200, current 5360 x 1440, maximum 32767 x 32767' "
        "'DP-1 connected 1920x1080+0+0 (normal left inverted right x axis y axis) 0mm x 0mm' "
        "'HDMI-0 connected primary 3440x1440+1920+0 (normal left inverted right x axis y axis) 0mm x 0mm' "
        "'HDMI-1 disconnected (normal left inverted right x axis y axis)'\n";
    write_test_file(xrandr_path, xrandr_script, sizeof(xrandr_script) - 1, 0755);

    CHECK(setenv("PATH", bin_directory, 1) == 0);
    DisplayInfo displays[MAX_DISPLAYS];
    size_t count = 0;
    char error[512] = {0};
    CHECK(query_displays(displays, &count, error, sizeof(error)));
    CHECK(count == 2);
    CHECK(strcmp(displays[0].name, "DP-1") == 0);
    CHECK(strcmp(displays[1].name, "HDMI-0") == 0);
    CHECK(displays[1].primary && primary_display_index(displays, count) == 1);
    CHECK(displays[1].width == 3440 && displays[1].height == 1440);
    CHECK(displays[1].x == 1920 && displays[1].y == 0);

    join_path(gamescope_path, bin_directory, "gamescope");
    static const char gamescope_script[] =
        "#!/bin/sh\n"
        "printf '%s\\n' \"$@\" > \"$RCT_TEST_GAMESCOPE_ARGS\"\n";
    write_test_file(gamescope_path, gamescope_script, sizeof(gamescope_script) - 1, 0755);
    join_path(args_path, root, "gamescope-args.txt");
    CHECK(setenv("RCT_TEST_GAMESCOPE_ARGS", args_path, 1) == 0);

    join_path(fixture_root, root, "gamescope-fixture");
    uint8_t initial[CONFIG_SIZE];
    create_game_fixture(fixture_root, game_path, config_path, initial);
    char *game_command[] = { (char *)"/bin/true", NULL };
    fflush(stdout);
    fflush(stderr);
    int saved_stdout = dup(STDOUT_FILENO), saved_stderr = dup(STDERR_FILENO);
    int null_output = open("/dev/null", O_WRONLY | O_CLOEXEC);
    CHECK(saved_stdout >= 0 && saved_stderr >= 0 && null_output >= 0);
    CHECK(dup2(null_output, STDOUT_FILENO) == STDOUT_FILENO);
    CHECK(dup2(null_output, STDERR_FILENO) == STDERR_FILENO);
    int result = run_game(game_path, game_command, displays[1].width, displays[1].height, 100,
                          (int)primary_display_index(displays, count));
    fflush(stdout);
    fflush(stderr);
    CHECK(dup2(saved_stdout, STDOUT_FILENO) == STDOUT_FILENO);
    CHECK(dup2(saved_stderr, STDERR_FILENO) == STDERR_FILENO);
    CHECK(close(saved_stdout) == 0 && close(saved_stderr) == 0 && close(null_output) == 0);
    CHECK(result != 0);

    char arguments[4096];
    CHECK(read_test_file(args_path, arguments, sizeof(arguments)) > 0);
    static const char expected[] =
        "-w\n1720\n-h\n720\n-W\n3440\n-H\n1440\n-S\ninteger\n-F\nnearest\n"
        "-r\n100\n--display-index\n1\n-f\n--force-grab-cursor\n"
        "--force-windows-fullscreen\n--\n/bin/true\n";
    CHECK(strcmp(arguments, expected) == 0);
}

int main(void) {
    char root_template[] = "/tmp/rct-ultrawide-tests.XXXXXX";
    char *root = mkdtemp(root_template);
    CHECK(root != NULL);

    test_parsers();
    test_unsupported_executable(root);
    test_config_backup_restore(root);
    test_steam_library_discovery(root);
    test_displays_and_gamescope(root);

    remove_tree(root);
    puts("All regression checks passed.");
    return 0;
}
