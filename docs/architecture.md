# Architecture

## Goal

TDSYNNEX Carbon Black Log Parser is intended to be a portable, local-only
Windows desktop application that helps engineers triage Carbon Black log
bundles from an extracted folder.

## Current skeleton

- `app/main.py` starts the PySide6 application.
- `app/bootstrap.py` prepares local portable directories.
- `app/ui/main_window.py` contains the minimal placeholder main window.
- `app/core/util/paths.py` resolves paths relative to the source checkout or
  future PyInstaller one-folder executable directory.
- `app/core/util/logging.py` defines the future scan log destination under the
  selected output folder.
- `rules/` contains JSON placeholders only.
- `templates/` contains placeholder report templates only.

## Planned boundaries

The app should remain local-only. Features must not add telemetry, update
checks, network calls, service installation, scheduled tasks, registry writes,
or admin-only runtime requirements.

## Future module intent

- `core/ingest`: collect selected files and folders.
- `core/extract`: unpack or normalize input bundles.
- `core/classify`: identify file types and known log sources.
- `core/scan`: coordinate scan jobs.
- `core/decode`: optional decoders.
- `core/rules`: JSON rule-pack loading and validation.
- `core/report`: CSV, HTML, and TXT report generation.
- `core/index`: optional local indexes, with SQLite considered later.
