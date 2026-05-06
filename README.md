# TDSYNNEX Carbon Black Log Parser

TDSYNNEX Carbon Black Log Parser is a portable, local-only Windows desktop tool
for deterministic triage of Carbon Black App Control log bundles. It is designed
to run from an extracted folder without installation.

## Portable local-only requirements

- No installer, MSI, or `setup.exe`.
- No administrator rights required.
- No Python required on the target engineer machine after packaging.
- No outbound network calls.
- No telemetry.
- No auto-update logic.
- No system registry writes.
- No Windows services or scheduled tasks.

## Current capabilities

- Minimal PySide6 desktop window titled `TDSYNNEX Carbon Black Log Parser`.
- Add files, add folders, drag/drop inputs, select output folder, start scan,
  and open the output folder.
- Per-scan workspaces under `output/scans/YYYYMMDD-HHMMSS/`.
- Safe recursive extraction for supported ZIP and TAR archives.
- Carbon Black App Control artifact classification.
- Deterministic Carbon Black App Control JSON rule hits.
- Line-by-line text scanning and binary string scanning.
- Optional helper detection for PCAP/PCAPNG, 7Z, CAB, EVTX, ETL, and PDF
  fallback behavior.
- Local report outputs:
  - `artifact_coverage.csv`
  - `all_hits.csv` (rule-based App Control hits)
  - `findings_by_rule.csv`
  - `findings_by_file.csv`
  - `missing_evidence_checklist.txt`
  - `triage_report.html`
  - `triage_report.txt`
  - optional `generic_hits.csv` only when `include_generic_hits` is enabled

## Getting the portable EXE

The repository does **not** store the built EXE or portable ZIP. Generated
artifacts such as `dist/`, `build/`, `*.exe`, and `*.zip` are intentionally
ignored so pull requests only contain source, tests, docs, rules, and packaging
instructions.

To get the portable EXE, run the GitHub Actions workflow
`.github/workflows/build-windows-portable.yml` (`build-windows-portable`) and
download the workflow artifact named `TDSYNNEX-CB-LogParser-portable`. The
workflow produces the portable ZIP from source on a Windows runner.

## How engineers run the portable app

1. Extract `TDSYNNEX-CB-LogParser.zip` to a writable local folder.
2. Run `TDSYNNEX-CB-LogParser.exe` directly.
3. Use **Add Files**, **Add Folder**, or drag/drop to add evidence.
4. Use **Select Output Folder** to choose where reports are written.
5. Click **Start Scan**.
6. Open the selected output folder and review the latest `scans/YYYYMMDD-HHMMSS`
   workspace.


## Drag-and-drop command-line mode

Engineers can scan customer artifacts without opening the GUI by dragging files,
folders, ZIPs, PDFs, and other logs onto the packaged EXE or onto
`DROP-CUSTOMER-LOGS-HERE.bat` in the portable folder. See `README-DROP-MODE.txt` for manual BAT validation steps and `docs/drop_mode_validation.md` for the source validation pass. From source, run:

```powershell
python -m app.drop_target "C:\Cases\customerlogs.zip" "C:\Cases\Broadcom StandardReport.pdf"
```

By default, reports are written to:

```text
%USERPROFILE%\Desktop\TDSYNNEX-CB-LogParser\Case-<CASE_NUMBER>-scan-YYYYMMDD-HHMMSS\
```

Use `--output "C:\Path\Output"` to choose a report folder, `--open-output` to
open the folder after completion, and `--pause` when launching from a batch file.
This mode uses the same App Control ingestion, scanner, rules, and report
pipeline as the packaged drag/drop entry point.

## Output location

Reports are written under the selected output folder. If no custom folder is
selected, the app uses the portable folder's local `output/` directory.

```text
output/scans/YYYYMMDD-HHMMSS/
  artifact_coverage.csv
  all_hits.csv
  generic_hits.csv (optional; only when include_generic_hits is enabled)
  findings_by_rule.csv
  findings_by_file.csv
  missing_evidence_checklist.txt
  triage_report.html
  triage_report.txt
  tdsynnex_carbon_black_log_parser.log
  decoded/
  extracted/
```

## Optional decoders

Optional helper tools are not required. Missing helpers never stop scans. The app
checks portable helper folders first, then `PATH`:

- `tools/tshark/tshark.exe`, then `PATH`, for PCAP/PCAPNG metadata.
- `tools/7zip/7z.exe` or `tools/7zip/7zz.exe`, then `PATH`, for `.7z` archives.
- `expand.exe` from `PATH` for CAB files.
- `wevtutil.exe` from `PATH` for EVTX files.
- `tracerpt.exe` from `PATH` for ETL files.
- Existing Python PDF text libraries if available; OCR is not implemented.

When a helper is missing or fails, `artifact_coverage.csv` records the decoder
status and limitation. PCAP/PCAPNG and ETL artifacts receive binary string
fallback when helper decoding is unavailable.

## What the app does not do

- Does not guarantee root cause.
- Does not perform remediation.
- Does not execute SQL.
- Does not OCR PDFs, screenshots, or images.
- Does not implement EDR or Carbon Black Cloud rules in v1.0.
- Does not require optional helper tools to be installed.

## Development setup

Use Python 3.11 or newer in a local virtual environment.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m app.main
```


## GitHub Actions portable build

A Windows GitHub Actions workflow builds the portable drag/drop ZIP without
creating an installer, MSI, or `setup.exe`.

To run it manually:

1. Open the repository in GitHub.
2. Select **Actions**.
3. Select **Build Windows Portable Drag/Drop ZIP**.
4. Click **Run workflow** and choose the `main` branch.
5. When the run finishes, open the completed workflow run and download the
   artifact named `TDSYNNEX-CB-LogParser-portable`.

The downloaded artifact contains `dist/TDSYNNEX-CB-LogParser-portable.zip`.
Do **not** use GitHub's **Code > Download ZIP** button for engineer handoff;
that downloads source code only and will not contain `TDSYNNEX-CB-LogParser.exe`.
See [`docs/download_portable_zip.md`](docs/download_portable_zip.md) for the
exact download path.

Engineers should unzip the portable ZIP, drag customer logs/ZIPs/PDFs/folders
onto `DROP-CUSTOMER-LOGS-HERE.bat`, wait for the scan to finish, and open
`triage_report.html` in the generated output folder.

## PyInstaller one-folder build

From a Windows development machine, build the portable drag/drop EXE and ZIP with:

```powershell
.\build-portable.ps1
```

Or call the PowerShell build through Command Prompt:

```bat
build-portable.bat
```

The build script creates/uses `.venv`, installs requirements and PyInstaller,
runs tests, invokes `packaging\pyinstaller\drop_target.spec`, verifies the EXE,
copies the drop-mode BAT/README into `dist\TDSYNNEX-CB-LogParser\`, and creates:

```text
dist\TDSYNNEX-CB-LogParser-portable.zip
```

Manual PyInstaller command if the environment is already prepared:

```powershell
pyinstaller --clean --noconfirm packaging\pyinstaller\drop_target.spec
```

The portable folder is created at:

```text
dist\TDSYNNEX-CB-LogParser\
```

Expected portable layout:

```text
TDSYNNEX-CB-LogParser/
  TDSYNNEX-CB-LogParser.exe
  DROP-CUSTOMER-LOGS-HERE.bat
  README-DROP-MODE.txt
  rules/
  templates/
  config/
  tools/
```

## Portable ZIP creation

The build script creates `dist\TDSYNNEX-CB-LogParser-portable.zip` automatically.
If you need to recreate it manually from the `dist` directory:

```powershell
Compress-Archive -Path .\TDSYNNEX-CB-LogParser -DestinationPath .\TDSYNNEX-CB-LogParser-portable.zip -Force
```

Do not create an installer, MSI, or `setup.exe`.

## Code signing

If signing is required by release policy, sign
`dist\TDSYNNEX-CB-LogParser\TDSYNNEX-CB-LogParser.exe` after PyInstaller builds
it and before creating the ZIP. Signing credentials are not included in this
repository.

## Additional documentation

- Portable usage: [`docs/portable_usage.md`](docs/portable_usage.md)
- Ingestion and reports: [`docs/ingestion.md`](docs/ingestion.md)
- Acceptance checklist: [`docs/acceptance.md`](docs/acceptance.md)
