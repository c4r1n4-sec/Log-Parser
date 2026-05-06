# Portable Usage

TDSYNNEX Carbon Black Log Parser is distributed as a portable PyInstaller
one-folder package. It is not an installer and does not create an MSI,
`setup.exe`, Windows service, scheduled task, or registry keys.

## Portable package layout

The packaged folder is intended to be zipped and shared as:

```text
TDSYNNEX-CB-LogParser/
  TDSYNNEX-CB-LogParser.exe
  rules/
    app_control_rules.json
    kb_candidates.json
  templates/
    triage_report.html.j2
    triage_report.txt.j2
  config/
    defaults.json
  tools/
    README.txt
  output/
    README.txt
  README.txt
```

PyInstaller may also include its own internal dependency folders/files inside the
same one-folder build. Do not remove those files from the portable folder.

## Running from an extracted folder

1. Extract the portable ZIP to a writable local folder, for example:
   `C:\Tools\TDSYNNEX-CB-LogParser` or a case-specific working folder.
2. Run `TDSYNNEX-CB-LogParser.exe` directly.
3. Use **Add Files**, **Add Folder**, or drag/drop to add log files, folders, or
   ZIP bundles.
4. Use **Select Output Folder** to choose where reports should be written.
5. Click **Start Scan**.
6. Use **Open Output Folder** to open the latest output workspace.

No installation is required. Administrator rights are not required. Python is not
required on the target engineer machine after packaging.

## Local-only behavior

The app is designed for offline local triage:

- No telemetry.
- No outbound network calls.
- No auto-update logic.
- No system registry writes.
- No service or scheduled-task installation.
- No SQL execution against customer databases.

## Output reports

Each scan creates a timestamped workspace under the selected output folder:

```text
output/scans/YYYYMMDD-HHMMSS/
  artifact_coverage.csv
  all_hits.csv
  findings_by_rule.csv
  findings_by_file.csv
  missing_evidence_checklist.txt
  triage_report.html
  triage_report.txt
  tdsynnex_carbon_black_log_parser.log
  decoded/
  extracted/
```

## Optional decoder helpers

Optional helpers are never required for the app to run. The app checks the
portable `tools/` folder first and `PATH` second:

- `tools/tshark/tshark.exe`, then `PATH`, for PCAP/PCAPNG metadata.
- `tools/7zip/7z.exe` or `tools/7zip/7zz.exe`, then `PATH`, for `.7z` archives.
- `expand.exe` from `PATH` for CAB files.
- `wevtutil.exe` from `PATH` for EVTX files.
- `tracerpt.exe` from `PATH` for ETL files.
- Existing Python PDF text libraries if bundled/available; no OCR is performed.

If `tshark`, `7z`, `tracerpt`, `wevtutil`, or `expand` are missing or fail, the
scan continues. The relevant artifact is recorded in `artifact_coverage.csv` with
`decoder_status` and `limitations`; PCAP/PCAPNG and ETL also receive binary
string fallback when helper decoding is unavailable.

## What v1.0 does not do

- Does not guarantee root cause.
- Does not perform remediation.
- Does not execute SQL.
- Does not OCR scanned PDFs, screenshots, or images.
- Does not implement EDR or Carbon Black Cloud rules in v1.0.
- Does not require optional helper tools to be installed.

## Building the portable folder

From a Windows development machine with Python and dependencies installed:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install pyinstaller
pyinstaller --clean --noconfirm packaging\pyinstaller\app.spec
```

The resulting folder is:

```text
dist\TDSYNNEX-CB-LogParser\
```

## Creating a portable ZIP

From the `dist` directory:

```powershell
Compress-Archive -Path .\TDSYNNEX-CB-LogParser -DestinationPath .\TDSYNNEX-CB-LogParser.zip -Force
```

Do not create an MSI, `setup.exe`, or installer wrapper.

## Code signing

If signing is required by release policy, sign
`dist\TDSYNNEX-CB-LogParser\TDSYNNEX-CB-LogParser.exe` after PyInstaller builds
it and before creating the ZIP. Signing credentials are not stored in this
repository and are not required for development builds.

## Release handoff ZIPs and test summary

After building the PyInstaller one-folder package, create the requested handoff
artifacts from the repository root:

```powershell
python tools\create_release_artifacts.py
```

The script writes the following files under `release_artifacts/`:

- `TDSYNNEX-CB-LogParser-repository.zip` with the source repository contents,
  excluding Git internals, virtual environments, generated build folders, and
  local scan output.
- `TDSYNNEX-CB-LogParser-dist.zip` with `dist/TDSYNNEX-CB-LogParser/` when that
  portable build folder exists.
- `test_output_summary.txt` containing the exact pytest command, exit code, and
  captured pytest summary.

If a machine is only validating source artifacts and has not produced the
PyInstaller folder yet, run the script with `--allow-missing-dist`; the summary
will explicitly state that the dist ZIP was not created.

