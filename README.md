# RCT Ultrawide for Linux

A small native Linux launcher and runtime patch for **RollerCoaster Tycoon Deluxe** on Steam. The game remains the Windows version and must run through Proton. The program starts the Steam command under Gamescope, selects the windowed GDI renderer, and applies guarded changes to the running process so the renderer can use the active display's aspect ratio.

It does not include, modify, or redistribute `RCT.EXE` or other game files. The executable on disk is checked by SHA-256, and the patcher refuses unknown builds.

## Supported build and platform

- Game: Steam RollerCoaster Tycoon Deluxe, App ID `285310`
- Supported executable SHA-256: `bdfebd64383b231de0252fe0726523d1c45aa2c4da919c2d7ed8bfb7aaa05c76`
- Linux: x86-64
- Runtime: Steam + Proton, Gamescope, and an X display discoverable by `xrandr` (or pass the output size explicitly)
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

## Install for Steam

1. In Steam, right-click **RollerCoaster Tycoon Deluxe → Manage → Browse local files**. Note the path to `RCT.EXE`.
2. Run the downloaded executable's `configure` command with that path. For example:

   ```sh
   ./rct-ultrawide-linux-x86_64 configure "/path/to/RollerCoaster Tycoon Deluxe/RCT.EXE" \
     --launcher "$PWD/rct-ultrawide-linux-x86_64"
   ```

   `configure` checks the game build, saves `Data/Game.cfg` once as `Data/Game.cfg.rct-ultrawide.bak`, and changes only the display-mode byte to select the renderer that works under Proton. It prints the Steam launch option.

3. Paste the printed line into **Steam → Properties → General → Launch Options** for the game. It has this form:

   ```text
   "/absolute/path/to/rct-ultrawide-linux-x86_64" run -- %command%
   ```

4. Launch the game normally from Steam. The launcher detects the active X display, starts Gamescope full screen with nearest-neighbor integer scaling, and patches the matching process as soon as its renderer code is unpacked.

If your existing launch options include GPU or performance environment prefixes, keep those before the patcher command (for example, `gamemoderun "/path/to/rct-ultrawide-linux-x86_64" run -- %command%`). Replace any existing Gamescope command because this launcher starts Gamescope itself.

On a 3440×1440 display, it renders at 1720×720 and scales 2×. Automatic 2× scaling is used when the output is at least 2560×1080 and both dimensions are even; otherwise the game renders at the output size. The game adapts its view to the active output aspect ratio.

### Manual launch-option setup

If you want to skip `configure`, use the full path to the downloaded executable directly in Steam's Launch Options:

```text
"/path/to/rct-ultrawide-linux-x86_64" run -- %command%
```

The first launch will then save the backup and select the windowed renderer automatically.

If display detection is unavailable, specify the output size in the launch option:

```text
"/path/to/rct-ultrawide-linux-x86_64" run --output 3440x1440 -- %command%
```

An optional refresh rate can be supplied with `--refresh 100`.

## Commands

```text
rct-ultrawide doctor <path/to/RCT.EXE>
rct-ultrawide configure <path/to/RCT.EXE> [--launcher <path/to/rct-ultrawide>]
rct-ultrawide restore <path/to/RCT.EXE>
rct-ultrawide run [--output WIDTHxHEIGHT] [--refresh HZ] -- <Steam %command%>
```

- `doctor` verifies the supported build and reports the config, display, and Gamescope state without changing files.
- `configure` makes a one-time backup and selects windowed mode. It prints the Steam Launch Options string.
- `run` is the Steam launch wrapper. It only patches the game process started by that command.
- `restore` restores the saved display-mode byte in `Game.cfg`; any later changes to other settings are preserved. Remove the tool from Steam Launch Options to stop using it.

## What it changes

The patcher checks the installed executable's exact SHA-256 and expected 32-bit PE layout. At runtime it locates the mapped game file under `/proc`, verifies both instruction signatures, then changes only the process memory:

1. It raises the game's windowed surface width and height limits to the dimensions selected for Gamescope.
2. It changes the renderer's horizontal tile-row calculation from truncation to a ceiling division using the tile size loaded by the game. This handles partial 32- or 64-pixel edge blocks without writing past the renderer's row buffer.

The original game executable is never written. Runtime code changes disappear when the game exits. If the image hash, PE layout, memory map, or expected instructions differ, the tool refuses to patch and stops its Gamescope child with a diagnostic.

## Troubleshooting

- **Unsupported executable:** use Steam's original Deluxe depot and check that Steam finished validating the game files. The patch intentionally does not guess offsets for other builds.
- **Gamescope missing:** install Gamescope from your distribution, then restart Steam so its environment sees it.
- **Could not detect a display:** use `--output WIDTHxHEIGHT` in the Steam Launch Options.
- **Permission denied on `/proc/<pid>/mem`:** launch through the Steam Launch Options above, under the same Linux user as Steam. The launcher is the Gamescope parent so normal same-user process tracing rules can apply.
- **Steam cloud restores `Game.cfg`:** rerun `configure`; it is safe and keeps the original backup.
- **Restore:** run `rct-ultrawide restore "/path/to/RCT.EXE"`, then remove the Steam launch option.

The downloadable release is built on Ubuntu 24.04. Native Steam, Proton, Gamescope, and the installed Steam build above are the validated path; Flatpak Steam and other game executable builds are not yet verified.

## License

The patcher is MIT-licensed. RollerCoaster Tycoon Deluxe and its game files remain the property of their respective rights holders and are not included here.
