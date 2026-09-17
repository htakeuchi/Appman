# AppMan

`appman` is a small command line tool that installs AppImages as ordinary
desktop applications on **Omarchy / Arch Linux**. It validates the AppImage,
stores it in a managed location, extracts its icon, writes a freedesktop.org
`.desktop` launcher entry, and keeps a registry so apps can be listed, run,
removed and diagnosed later.

It is written in pure Python (standard library only) and does not need FUSE for
installation or inspection.

## Requirements

- Python 3.11+ (Python 3.14 recommended; zstd compressed AppImages need 3.14)
- A freedesktop.org compliant desktop environment (Omarchy ships one)
- `desktop-file-utils` for `update-desktop-database` (recommended)
- FUSE (`fuse3`) to run AppImages by mounting; otherwise `appman` falls back to
  `APPIMAGE_EXTRACT_AND_RUN=1`

## Installation

From a checkout:

```sh
ln -s "$PWD/bin/appman" ~/.local/bin/appman
```

or with `uv`:

```sh
uv tool install .
```

## Usage

```sh
appman install ./SomeApp-1.2.3.AppImage   # validate, copy, extract icon, create launcher
appman list                               # list installed apps
appman info SomeApp                       # details about an app
appman run SomeApp [args...]              # launch it
appman remove SomeApp                     # uninstall (asks for confirmation)
appman doctor SomeApp                     # diagnose why it will not run
```

Useful flags:

- `install --dry-run` / `--force` / `--yes`
- `remove --dry-run` / `--yes` / `--backup`
- `doctor --deep` (executes the AppImage runtime and extracts the payload to
  verify it; the default `doctor` is fully static and never runs the AppImage)
- `list --json`, `info --json`, `doctor --json` for scripting
- Set `APPMAN_HOME` and `XDG_DATA_HOME` to relocate all state (used by tests)

## What `install` does

1. Verifies the file is an ELF with the AppImage magic (`AI\x02`).
2. Locates the embedded SquashFS payload from the ELF section header table
   (falling back to a validated scan) and reads its super block.
3. Reads the root `.desktop` file from the SquashFS payload to obtain the name,
   version (`X-AppImage-Version`), comment, categories, `StartupWMClass` and
   extra `Exec` arguments.
4. Extracts the best icon (`.DirIcon` / `Icon=` lookup, preferring SVG then the
   largest PNG) from the payload.
5. Copies the AppImage to `~/.local/share/appman/apps/<id>.AppImage` (mode 0755).
6. Installs the icon to
   `~/.local/share/icons/hicolor/{512x512,scalable}/apps/appman-<id>.<ext>`.
7. Writes `~/.local/share/applications/appman-<id>.desktop` pointing at the
   installed AppImage, so the Omarchy launcher picks it up like any other app.
8. Records the install in `~/.local/share/appman/db/<id>.json`.
9. Runs `update-desktop-database` and `gtk-update-icon-cache` (best effort).

## Safety model

- Existing installs are never overwritten silently:
  - reinstalling the *same* file is a no-op,
  - installing a *different* file with the same id asks for confirmation (or
    requires `--force`),
  - the previous AppImage is moved to `~/.local/share/appman/backups/` before
    being replaced.
- Broken files are rejected before anything is written. `--force` can install a
  damaged AppImage for recovery purposes, with metadata derived from the file
  name.
- `remove` only deletes paths that live inside AppMan's own directories, and
  refuses to guess when the file is missing or the path is unexpected.
- All file writes are atomic (write to a temp file, then `os.replace`) with
  best-effort rollback if an install fails midway.
- User data (e.g. `~/.config/<app>`) is never touched.

## State layout

```
~/.local/share/appman/
├── apps/<id>.AppImage        installed payloads (self-contained)
├── backups/                  previous payloads kept on replace
├── db/<id>.json              registry records
~/.local/share/applications/appman-<id>.desktop
~/.local/share/icons/hicolor/.../apps/appman-<id>.<png|svg>
```

## Development / tests

The test suite uses `unittest`. Most tests run without any fixture; the
SquashFS reader and installer tests need a real AppImage. Point
`APPMAN_TEST_APPIMAGE` at any type 2 AppImage to enable them:

```sh
APPMAN_TEST_APPIMAGE=/path/to/App.AppImage \
  PYTHONPATH=src:tests python3 -m unittest discover -s tests -v
```

Tests that need an AppImage are skipped automatically when none is found, and
each one that inspects image contents skips gracefully when the fixture lacks
the relevant entry.

## Limitations

- Only AppImage **type 2** is supported; the obsolete type 1 (ISO 9660) is
  detected and rejected with a clear message.
- The built-in SquashFS reader handles `gzip`, `xz`, `lzma` and `zstd`
  (zstd needs Python 3.14+). For other compressions such as `lzo` and `lz4`,
  AppMan falls back to `unsquashfs` when `squashfs-tools` is installed;
  otherwise it reports a clear error instead of guessing.
- Application metadata comes from the AppImage's embedded `.desktop` file. When
  it is missing, the file name and `--force` fallback are used.
- `run` executes the AppImage in place; it does not sandbox or verify the
  application code itself.
