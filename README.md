# RCT Ultrawide for Linux

A small native Linux launcher and runtime patch for **RollerCoaster Tycoon Deluxe** on Steam. The game remains the Windows version and must run through Proton. The program starts the Steam command under Gamescope, selects the windowed GDI renderer, and applies guarded changes to the running process so the renderer can use the active display's aspect ratio.

It does not include, modify, or redistribute `RCT.EXE` or other game files. The executable on disk is checked by SHA-256, and the patcher refuses unknown builds.

## Supported build and platform

- Game: Steam RollerCoaster Tycoon Deluxe, App ID `285310`
- Supported executable SHA-256: `bdfebd64383b231de0252fe0726523d1c45aa2c4da919c2d7ed8bfb7aaa05c76`
- Linux: x86-64
- Runtime: Steam + Proton, Gamescope, and XRandR display discovery (or pass the output size explicitly)
- Build dependency: a C11 compiler, static glibc development files, and a static-PIE-capable linker; release builds have no third-party libraries

Other Steam depots or repacks may use different executable bytes. They are unsupported until their exact build and code layout are independently checked and added to the allowlist.

## Download

Open the repository's **Releases** page and download `rct-ultrawide-linux-x86_64`. Optionally download the adjacent `.sha256` file to check the release asset. Then make it executable:

```sh
chmod +x ./rct-ultrawide-linux-x86_64
sha256sum -c rct-ultrawide-linux-x86_64.sha256
```

To build from source instead:

```sh
make release
```

This creates `build/rct-ultrawide-linux-x86_64` and a SHA-256 checksum file.

To run the regression suite used in CI:

```sh
make test
```

The suite uses disposable fixtures and stub display/Gamescope commands. It checks Steam library discovery, selected-display Gamescope arguments, config backup and restoration, and refusal of an unsupported executable. It does not include or need the game's files.

## Guided installation for Steam

Run `install` from a terminal. It finds a unique Steam App 285310 installation in the standard Steam libraries, verifies the executable, backs up `Data/Game.cfg` once, and selects the windowed renderer:

```sh
./rct-ultrawide-linux-x86_64 install --launcher "$PWD/rct-ultrawide-linux-x86_64"
```

If the game is in a nonstandard library or multiple copies are installed, pass the intended executable explicitly:

```sh
./rct-ultrawide-linux-x86_64 install "/path/to/RollerCoaster Tycoon Deluxe/RCT.EXE" \
  --launcher "$PWD/rct-ultrawide-linux-x86_64"
```

If your existing Steam options start with environment variables or a performance launcher, pass that prefix with `--prefix`. The tool prints a replacement launch option with the prefix in front of the patcher; it never edits Steam's local configuration:

```sh
./rct-ultrawide-linux-x86_64 install "/path/to/RollerCoaster Tycoon Deluxe/RCT.EXE" \
  --launcher "$PWD/rct-ultrawide-linux-x86_64" \
  --prefix '__NV_PRIME_RENDER_OFFLOAD=1 __GLX_VENDOR_LIBRARY_NAME=nvidia gamemoderun'
```

Paste the printed line into **Steam → Properties → General → Launch Options**. Then launch the game normally from Steam. The launcher detects the primary XRandR output, starts Gamescope full screen with nearest-neighbor integer scaling, and patches the matching process as soon as its renderer code is unpacked.

Replace any existing Gamescope command because this launcher starts Gamescope itself. The optional `--prefix` is a shell fragment: enter only the existing leading environment assignments and launch wrappers, without `%command%`.

On a 3440×1440 display, it renders at 1720×720 and scales 2×. Automatic 2× scaling is used when the output is at least 2560×1080 and both dimensions are even; otherwise the game renders at the output size. The game adapts its view to the active output aspect ratio.

### Manual launch-option setup

If you want to skip `configure`, use the full path to the downloaded executable directly in Steam's Launch Options:

```text
"/path/to/rct-ultrawide-linux-x86_64" run -- %command%
```

The first launch will then save the backup and select the windowed renderer automatically.

List detected displays with their indexes and resolutions:

```sh
./rct-ultrawide-linux-x86_64 displays
```

By default, the primary display is selected. To choose another display, pass its listed index. You can also override the size Gamescope should use:

```text
"/path/to/rct-ultrawide-linux-x86_64" run --monitor 1 -- %command%
"/path/to/rct-ultrawide-linux-x86_64" run --monitor 1 --output 2560x1440 -- %command%
```

If XRandR detection is unavailable, specify the output size explicitly:

```text
"/path/to/rct-ultrawide-linux-x86_64" run --output 3440x1440 -- %command%
```

An optional refresh rate can be supplied with `--refresh 100`.

## Commands

```text
rct-ultrawide doctor <path/to/RCT.EXE>
rct-ultrawide displays
rct-ultrawide install [path/to/RCT.EXE] [--launcher <path>] [--prefix <existing-prefix>]
rct-ultrawide uninstall [path/to/RCT.EXE]
rct-ultrawide configure <path/to/RCT.EXE> [--launcher <path/to/rct-ultrawide>]
rct-ultrawide restore <path/to/RCT.EXE>
rct-ultrawide run [--monitor INDEX] [--output WIDTHxHEIGHT] [--refresh HZ] -- <Steam %command%>
```

- `doctor` verifies the supported build and reports the config, backup, display, Gamescope, and Steam runtime state without changing files.
- `displays` lists active XRandR outputs. `--monitor INDEX` forwards the selected index to Gamescope. Multi-monitor index correspondence has not yet been verified.
- `install` validates the build, makes a one-time backup, selects windowed mode, and prints the Steam command. It does not write Steam settings.
- `uninstall` restores the backed-up display-mode byte and reminds you to remove the patcher command while keeping your launch prefixes.
- `configure` and `restore` remain available as the original manual commands.
- `run` is the Steam launch wrapper. It only patches the game process started by that command.
- `restore` restores the saved display-mode byte in `Game.cfg`; any later changes to other settings are preserved.

## What it changes

The patcher checks the installed executable's exact SHA-256 and expected 32-bit PE layout. At runtime it locates the mapped game file under `/proc`, verifies both instruction signatures, then changes only the process memory:

1. It raises the game's windowed surface width and height limits to the dimensions selected for Gamescope.
2. It changes the renderer's horizontal tile-row calculation from truncation to a ceiling division using the tile size loaded by the game. This handles partial 32- or 64-pixel edge blocks without writing past the renderer's row buffer.

The original game executable is never written. Runtime code changes disappear when the game exits. If the image hash, PE layout, memory map, or expected instructions differ, the tool refuses to patch and stops its Gamescope child with a diagnostic.

## Troubleshooting

- **Unsupported executable:** use Steam's original Deluxe depot and check that Steam finished validating the game files. The patch intentionally does not guess offsets for other builds.
- **Gamescope missing:** install Gamescope from your distribution, then restart Steam so its environment sees it.
- **Wrong display selected:** run `rct-ultrawide displays`, then use `--monitor INDEX` in the Steam Launch Options.
- **Could not detect a display:** use `--output WIDTHxHEIGHT` in the Steam Launch Options.
- **Permission denied on `/proc/<pid>/mem`:** launch through the Steam Launch Options above, under the same Linux user as Steam. The launcher is the Gamescope parent so normal same-user process tracing rules can apply.
- **Steam cloud restores `Game.cfg`:** rerun `configure`; it is safe and keeps the original backup.
- **Restore:** run `rct-ultrawide restore "/path/to/RCT.EXE"`, then remove the Steam launch option.

The downloadable release is built on Ubuntu 24.04. Native Steam, Proton, Gamescope, and the installed Steam build above are the validated path; Flatpak Steam and other game executable builds are not yet verified. See [the validation record](docs/VALIDATION.md) for tested gameplay steps and remaining coverage.

## License

The patcher is MIT-licensed. RollerCoaster Tycoon Deluxe and its game files remain the property of their respective rights holders and are not included here.
