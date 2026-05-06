# Drag/drop EXE and BAT Validation

Validation date: 2026-05-06

Scope: source drag/drop CLI behavior, synthetic customer bundle processing,
report generation, BAT/spec static coverage, and portable build readiness for
`TDSYNNEX-CB-LogParser.exe`.

## Synthetic fixture

The validation fixture is generated at test runtime by
`tests/integration/test_drop_mode_validation.py`. Generated customer-like files
(`*.log`, `*.zip`, binary captures, and scan outputs) are not stored in git. The
runtime fixture contains:

- `ReporterLog-test.txt` with SQL timeout and `AntibodyMetadataLookup` evidence.
- `trace.bt9` with `Server Communication`, `GetSslError[16]`, and
  connected-waiting evidence.
- `ServerLog.bt9` with `AppCWebServer` and `add_server_role` evidence.
- `binary-test.bin` with binary-wrapped printable CDC connectivity text.
- `nested-logs.zip` containing `nested/nested-reviewed.log`.

## Commands run

```bash
python -m ruff check app tests tools/create_release_artifacts.py
PYENV_VERSION=3.11.14 python -m pytest tests/integration/test_drop_mode_validation.py -q
PYENV_VERSION=3.11.14 python -m pytest -q
PYENV_VERSION=3.11.14 python -m compileall app tests tools/create_release_artifacts.py
# Source CLI smoke runs are covered by tests that generate a temporary fixture.
PYENV_VERSION=3.11.14 python -m PyInstaller --version
pwsh -NoProfile -ExecutionPolicy Bypass -File ./build-portable.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./build-portable.ps1
```

## Source CLI validation output summary

Custom output run:

```text
Scan started
Inputs received: 1
Output folder: /tmp/drop-mode-validation-custom
Files discovered: 6
Files scanned: 6
Findings count: 7
Report path: /tmp/drop-mode-validation-custom/triage_report.html
```

Default Desktop case output run with `HOME=/tmp/drop-mode-validation-home`:

```text
Output folder: /tmp/drop-mode-validation-home/Desktop/TDSYNNEX-CB-LogParser/Case-60114450-scan-20260506-130220
```

Pause run completed normally and printed:

```text
Press Enter to close...
```

## Pass/fail table

| # | Requirement | Result | Evidence |
|---|-------------|--------|----------|
| 1 | Run CLI entry point against synthetic folder. | PASS | `pytest tests/integration/test_drop_mode_validation.py` generated a temporary fixture and completed the source CLI run with exit code 0. |
| 2 | Generate `artifact_coverage.csv`. | PASS | Present in `/tmp/drop-mode-validation-custom`. |
| 3 | Generate `all_hits.csv`. | PASS | Present in `/tmp/drop-mode-validation-custom`. |
| 4 | Generate `findings_by_rule.csv`. | PASS | Present in `/tmp/drop-mode-validation-custom`. |
| 5 | Generate `findings_by_file.csv`. | PASS | Present in `/tmp/drop-mode-validation-custom`. |
| 6 | Generate `missing_evidence_checklist.txt`. | PASS | Present in `/tmp/drop-mode-validation-custom`. |
| 7 | Generate `triage_report.html`. | PASS | Present in `/tmp/drop-mode-validation-custom`; path printed by CLI. |
| 8 | Generate `triage_report.txt`. | PASS | Present in `/tmp/drop-mode-validation-custom`. |
| 9 | Confirm `APPC_SQL_TIMEOUT`. | PASS | Found in `all_hits.csv`. |
| 10 | Confirm `APPC_CERT_CN_MISMATCH`. | PASS | Found in `all_hits.csv`. |
| 11 | Confirm `APPC_DISC_AGENT_41002`. | PASS | Found in `all_hits.csv`. |
| 12 | Confirm `APPC_SQL_ROLE_DSN_APPCWEBSERVER`. | PASS | Found in `all_hits.csv`. |
| 13 | Confirm binary string scan does not flood rule reports. | PASS | `generic_hits.csv` is not created by default and `triage_report.html` does not contain `GENERIC_SEARCH`; generic binary matches remain optional evidence when `include_generic_hits` is enabled. |
| 14 | Confirm nested ZIP contents are reviewed. | PASS | `artifact_coverage.csv` contains `nested-reviewed.log`. |
| 15 | Confirm KBs are labeled as KB candidates only. | PASS | Hit rows use `KB candidate ...`; no KB wording is marked confirmed. |
| 16 | Confirm no report says `confirmed root cause`. | PASS | `triage_report.txt`, `triage_report.html`, and `missing_evidence_checklist.txt` were checked case-insensitively. |
| 17 | Confirm automatic Desktop case output when `--output` is omitted. | PASS | Output was created under `/tmp/drop-mode-validation-home/Desktop/TDSYNNEX-CB-LogParser/Case-60114450-scan-...`. |
| 18 | Confirm custom `--output` works. | PASS | Reports were written directly to `/tmp/drop-mode-validation-custom`. |
| 19 | Confirm `--pause` behavior does not break normal scans. | PASS | Scan completed and waited for Enter before closing. |
| 20 | Build portable EXE with PyInstaller if available. | NOT RUN | `python -m PyInstaller --version` failed because PyInstaller is not installed in this Linux validation environment. |
| 21 | Run built EXE against synthetic folder if available. | NOT RUN | No built EXE was available because PyInstaller could not be run here. |
| 22 | Run Windows build script if possible. | NOT RUN | `pwsh` and `powershell.exe` are not installed in this Linux validation environment. |

## Files generated during source validation

The custom source run generated these files under `/tmp/drop-mode-validation-custom/`:

```text
all_hits.csv
artifact_coverage.csv
findings_by_file.csv
findings_by_rule.csv
missing_evidence_checklist.txt
tdsynnex_carbon_black_log_parser.log
triage_report.html
triage_report.txt
```

The default-output source run generated the same report set under:

```text
/tmp/drop-mode-validation-home/Desktop/TDSYNNEX-CB-LogParser/Case-60114450-scan-20260506-130220/
```

The pause source run generated the same report set under:

```text
/tmp/drop-mode-validation-pause/
```

## Known limitations

- PyInstaller was not installed in this Linux validation environment, so the
  portable Windows EXE was not built here.
- `pwsh` and `powershell.exe` were not installed in this Linux validation
  environment, so `build-portable.ps1` could not be executed here.
- Windows drag/drop shell behavior for dropping files onto the BAT must be
  manually validated on a Windows packaging or engineer workstation.
- Generic keyword hits are excluded from `all_hits.csv`, findings counts, and
  triage reports by default. Set `reports.include_generic_hits` to `true` in
  `config/defaults.json` only when generic keyword evidence is explicitly needed;
  this writes `generic_hits.csv` separately.
- The tool records deterministic observations and KB candidates only. It does
  not prove root cause automatically.

## Manual Windows drag/drop test steps

1. On Windows, run the portable build:

   ```powershell
   .\build-portable.ps1
   ```

2. Confirm the portable folder and ZIP exist:

   ```text
   dist\TDSYNNEX-CB-LogParser\TDSYNNEX-CB-LogParser.exe
   dist\TDSYNNEX-CB-LogParser\DROP-CUSTOMER-LOGS-HERE.bat
   dist\TDSYNNEX-CB-LogParser-portable.zip
   ```

3. Unzip the portable package.
4. Drag a customer ZIP or folder onto `DROP-CUSTOMER-LOGS-HERE.bat`.
5. Wait for the scan to complete.
6. Open `triage_report.html` in the generated output folder.
7. Repeat with a path containing spaces and with multiple dropped files/folders.
8. Confirm the BAT leaves the console open because it calls the EXE with
   `--open-output --pause`.
