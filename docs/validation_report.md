# Validation Report - TDSYNNEX Carbon Black Log Parser App Control v1.0

Validation date: 2026-05-06
Repository branch: current working branch
Validation scope: portable App Control v1.0 behavior, packaging documentation, tests, and PyInstaller one-folder build readiness.

## Executive summary

The repository passes the automated unit and integration validation suite in this
environment. The code and packaging metadata are configured for a portable
PyInstaller one-folder build named `TDSYNNEX-CB-LogParser`.

A packaged Windows executable was not built in this Linux validation environment
because PyInstaller is not installed here. The expected portable build folder,
when built on a Windows packaging machine, is:

```text
dist/TDSYNNEX-CB-LogParser/
```

No application code changes were required to fix acceptance failures during this
validation pass.

## Acceptance criteria

| # | Requirement | Status | Validation evidence |
|---:|---|---|---|
| 1 | Runs from an extracted folder without installation. | PASS | PyInstaller one-folder spec emits `dist/TDSYNNEX-CB-LogParser/`; docs instruct direct EXE execution from extracted ZIP. |
| 2 | Does not require admin rights. | PASS | No admin-only operations found; docs and portable README state no admin rights required. |
| 3 | Does not require Python on the target machine after PyInstaller packaging. | PASS | PyInstaller one-folder packaging is documented and configured; target layout includes EXE and bundled assets. Runtime packaged EXE was not built in this environment. |
| 4 | Makes no outbound network calls. | PASS | Code search found no network client imports/calls such as `requests`, `urllib`, `socket`, `httpx`, `aiohttp`, or Qt network usage. |
| 5 | Does not use telemetry or auto-update logic. | PASS | Code search found no telemetry or auto-update implementation; defaults explicitly disable telemetry and auto-update. |
| 6 | Accepts files, folders, and ZIP archives. | PASS | GUI supports Add Files/Add Folder/drag-drop; tests exercise folder, ZIP, and nested ZIP inputs. |
| 7 | Recursively extracts supported archives safely. | PASS | Unit tests cover normal ZIP and nested ZIP extraction. |
| 8 | Prevents zip-slip/path traversal. | PASS | Unit test verifies `../evil.txt` is refused and not written outside the workspace. |
| 9 | Records every artifact in `artifact_coverage.csv`. | PASS | Unit/integration tests assert coverage rows for discovered files, extracted files, unsupported artifacts, and decoded outputs. |
| 10 | Scans every readable text-like file line by line. | PASS | UTF-8, UTF-16, latin-1 fallback, context, and synthetic bundle tests pass. |
| 11 | Records file path and line number for text hits. | PASS | Scanning tests assert line-numbered hits in `all_hits.csv`. |
| 12 | Binary-scans opaque files and records byte offset or fragment location when possible. | PASS | Binary string test asserts byte offset for printable string hit. |
| 13 | Produces all required report files. | PASS | Integration and summary tests assert `artifact_coverage.csv`, `all_hits.csv`, `findings_by_rule.csv`, `findings_by_file.csv`, `missing_evidence_checklist.txt`, `triage_report.html`, and `triage_report.txt`. |
| 14 | Applies App Control JSON rules. | PASS | App Control rule tests assert SQL timeout, GetSslError, tamper, AppCWebServer, and kernel assertion rule hits. |
| 15 | Labels Broadcom KBs as KB candidates only. | PASS | Rule-hit tests assert `KB candidate` labels; KB JSON stores `candidate_only`; reports use candidate terminology. |
| 16 | Does not claim confirmed root cause. | PASS | Summary and integration tests assert generated HTML/TXT/checklist reports do not contain `Confirmed root cause`; report language uses observed evidence and likely issue family. |
| 17 | Does not require Broadcom StandardReport. | PASS | Code search found no dependency on `StandardReport`; CB Analysis output is optional evidence only. |
| 18 | Does not require `CarbonBlackDBResults.txt`. | PASS | Code search found no dependency on `CarbonBlackDBResults.txt`. |
| 19 | Does not execute remediation. | PASS | Code search found no remediation execution path; docs state remediation is not performed. |
| 20 | Does not execute SQL scripts. | PASS | Code search found no SQL execution helpers such as `sqlcmd`; docs state SQL is not executed. |
| 21 | Does not crash when `tshark`, `7z`, `tracerpt`, `wevtutil`, or `expand` are unavailable. | PASS | Optional decoder tests mock missing/failed helpers and assert scans continue with decoder status/limitations recorded. |

## Commands executed

```bash
python -m ruff check app tests
python -m pytest -q
python -m compileall app tests
python - <<'PY'
from app.core.util.config import load_defaults
print(load_defaults()['application']['name'])
PY
python -m PyInstaller --version
rg -n "\b(import|from)\s+(requests|urllib|httpx|aiohttp|socket|websocket|ftplib|smtplib)|QNetwork|UrlRequest|telemetry|auto.?update|winreg|subprocess\.run\(.*(curl|wget|sqlcmd|powershell)" app -S
rg -n "requests|urllib|httpx|aiohttp|socket|websocket|telemetry|auto.?update|update check|winreg|registry|RegSet|CreateService|schtasks|ScheduledTask|subprocess.*sql|sqlcmd|powershell|Invoke-WebRequest|curl|wget|StandardReport|CarbonBlackDBResults|root cause|confirmed root cause|remediation|execute SQL|DROP |ALTER |INSERT |UPDATE " app rules docs README.md packaging tests -S
```

## Test results

- `python -m ruff check app tests`: PASS (`All checks passed!`).
- `python -m pytest -q`: PASS (`27 passed, 1 skipped`). The skipped test is the existing PySide6 window-title smoke test when PySide6 is not installed in this environment.
- `python -m compileall app tests`: PASS.
- `load_defaults()` smoke check: PASS; returned `TDSYNNEX Carbon Black Log Parser`.
- `python -m PyInstaller --version`: WARNING; PyInstaller is not installed in this validation environment, so a Windows one-folder executable was not built here.

## Failures found

No failing acceptance criteria were found in source/test validation.

## Files changed to fix failures

None. No acceptance failures required code fixes during this validation pass.

## Files changed for this validation deliverable

- `docs/validation_report.md`

## Known limitations

- The Windows PyInstaller executable was not built or launched in this Linux validation environment because PyInstaller is not installed here.
- Final packaged runtime validation should be performed on a Windows packaging machine after running the PyInstaller command below.
- Optional helpers (`tshark`, `7z`, `expand.exe`, `wevtutil.exe`, `tracerpt.exe`) are opportunistic. Missing helpers are expected and are recorded in report limitations/status rather than treated as fatal errors.
- PDF support is text extraction only when an existing Python PDF dependency is available; OCR is not implemented.
- EDR and Carbon Black Cloud rules are not implemented in v1.0.
- Reports provide observed evidence, likely issue family, missing evidence, and KB candidates; they do not guarantee root cause or perform remediation.

## Final portable build instructions

Run on a Windows packaging machine with Python available for the build step:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install pyinstaller
pyinstaller --clean --noconfirm packaging\pyinstaller\drop_target.spec
```

Expected portable build folder:

```text
dist\TDSYNNEX-CB-LogParser\
```

Expected portable contents:

```text
TDSYNNEX-CB-LogParser\
  TDSYNNEX-CB-LogParser.exe
  rules\
  templates\
  config\
  tools\
  output\
  README.txt
```

## Portable ZIP creation instructions

From the `dist` directory on Windows:

```powershell
Compress-Archive -Path .\TDSYNNEX-CB-LogParser -DestinationPath .\TDSYNNEX-CB-LogParser.zip -Force
```

Do not create an MSI, `setup.exe`, or installer wrapper.

## Signing note

If signing is required by release policy, sign this executable after PyInstaller
builds it and before creating the ZIP:

```text
dist\TDSYNNEX-CB-LogParser\TDSYNNEX-CB-LogParser.exe
```

Signing credentials were not available in this validation environment and are
not stored in this repository.
