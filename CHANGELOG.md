# Changelog

## 0.2.0

- Select the primary XRandR display by default, list active displays, and pass an explicit monitor index to Gamescope.
- Add guided Steam install/uninstall commands with standard-library discovery and launch-prefix preservation.
- Expand `doctor` to report backup validity, active displays, Gamescope, and Steam runtime environment.
- Return a failure status when the wrapped game exits before runtime patching is confirmed.
- Add a gameplay validation record with observed behavior and remaining coverage.

## 0.1.0

- Initial Linux x86-64 launcher for the Steam Deluxe executable build listed in the README.
- Guarded windowed surface-limit and tile-stride runtime patches.
- Gamescope integer scaling, display-size override, Game.cfg backup, and restore commands.
