# Gameplay validation

This record tracks observed behavior separately from planned checks. The game
remains the Windows Steam build running through Proton; the patcher changes
only the live process and the documented `Game.cfg` display-mode byte.

## Observed locally for 0.2.0

- Linux x86-64, native Steam, Proton Experimental, Gamescope 3.14.24, X11.
- Supported `RCT.EXE` SHA-256: `bdfebd64383b231de0252fe0726523d1c45aa2c4da919c2d7ed8bfb7aaa05c76`.
- Primary output: 3440×1440. Gamescope ran the game at 1720×720 and scaled it 2×.
- The MicroProse splash advanced to the RollerCoaster Tycoon title screen.
- The title-screen new-game control opened the scenario picker. Selecting
  **Forest Frontiers** opened the scenario view and its in-game toolbar/status
  bar.
- The pointer reached the game through its XWayland window; the scenario
  picker responded to a click at the expected in-game coordinate.
- The in-game file menu opened from the toolbar. No save was created, and the
  test session was closed without saving.
- A local install/uninstall fixture confirmed that installation changes only
  byte 23 of `Data/Game.cfg`, creates a one-time backup, and restores the saved
  byte while preserving all other settings. The emitted Steam command retained
  a supplied environment/performance prefix.
- `displays` and `doctor` reported the active 3440×1440 primary output and the
  valid game build/configuration.
- A stubbed Gamescope argument check confirmed `run --monitor 0` forwards
  `--display-index 0` and selects 1720×720 for the 3440×1440 output. It also
  confirmed that an early child exit before patch confirmation returns failure.

## Still to verify

- Completing a scenario-start flow and interacting with rides, map edges,
  build tools, and menus for longer sessions.
- Opening and cancelling both load and save dialogs; save/load round trips
  should be tested against a disposable save.
- Alt+Tab, focus restoration, and clean exit through the game UI.
- Multi-monitor selection on systems with more than one active output. The
  local validation machine has one monitor, so only display index 0 was
  observed.
- Other refresh rates, 16:9 displays, and ultrawide resolutions that do not
  scale by an integer factor of two.

Do not mark a row complete based only on the game launching. Record the output
resolution, Gamescope input resolution, executable hash, Proton version,
scenario, and whether the action changed a save file.
