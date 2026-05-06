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
  DROP-CUSTOMER-LOGS-HERE.bat
  README-DROP-MODE.txt
  README.txt
```

PyInstaller may also include its own internal dependency folders/files inside the
same one-folder build. Do not remove those files from the portable folder.

## Running from an extracted folder

1. Extract the portable ZIP to a writable local folder, for example:
   `C:\Tools\TDSYNNEX-CB-LogParser` or a case-specific working folder.
2. Drag customer logs, ZIPs, PDFs, or folders onto `TDSYNNEX-CB-LogParser.exe`.
3. Or drag artifacts onto `DROP-CUSTOMER-LOGS-HERE.bat` to keep the console open
   after the scan completes.
4. Review the generated report folder printed in the console output.

No installation is required. Administrator rights are not required. Python is not
required on the target engineer machine after packaging.

The same mode can be run explicitly:

```powershell
TDSYNNEX-CB-LogParser.exe "C:\Cases\customerlogs.zip" "C:\Cases\Broadcom StandardReport.pdf"
```

From source, the equivalent command is:

```powershell
python -m app.drop_target "C:\Cases\customerlogs.zip" "C:\Cases\Broadcom StandardReport.pdf"
```

Use `--output "C:\Path\Output"` to choose a report folder, `--open-output` to
open the folder after completion, and `--pause` to wait for Enter before the
console closes. This command-line mode reuses the shared App Control scan/report
pipeline and does not add Carbon Black Cloud or EDR logic. See
`docs/drop_mode_validation.md` for the source validation pass and manual Windows
drag/drop test steps.

## Local-only behavior

The app is designed for offline local triage:

- No telemetry.
- No outbound network calls.
- No auto-update logic.
- No system registry writes.
- No service or scheduled-task installation.
- No SQL execution against customer databases.

## Output reports

Drag/drop scans write reports to the selected `--output` folder or, by default,
to a case-specific timestamped Desktop folder:

```text
%USERPROFILE%\Desktop\TDSYNNEX-CB-LogParser\Case-<CASE_NUMBER>-scan-YYYYMMDD-HHMMSS\
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

From a Windows development machine with Python available:

```powershell
.\build-portable.ps1
```

Or from Command Prompt:

```bat
build-portable.bat
```

The script creates/uses `.venv`, installs requirements and PyInstaller, runs
tests, runs `packaging\pyinstaller\drop_target.spec`, verifies the EXE, copies
`DROP-CUSTOMER-LOGS-HERE.bat` and `README-DROP-MODE.txt` into the portable
folder, and creates `dist\TDSYNNEX-CB-LogParser-portable.zip`.

Manual PyInstaller command if the environment is already prepared:

```powershell
pyinstaller --clean --noconfirm packaging\pyinstaller\drop_target.spec
```

The resulting folder is:

```text
dist\TDSYNNEX-CB-LogParser\
```

## Creating a portable ZIP

`build-portable.ps1` creates the ZIP automatically at:

```text
dist\TDSYNNEX-CB-LogParser-portable.zip
```

Manual ZIP creation from the `dist` directory:

```powershell
Compress-Archive -Path .\TDSYNNEX-CB-LogParser -DestinationPath .\TDSYNNEX-CB-LogParser-portable.zip -Force
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

