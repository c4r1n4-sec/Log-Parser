# Final portable drag/drop validation

Validation date: 2026-05-06  
Validation environment: Linux container at `/workspace/Log-Parser` with Python 3.10.19.  
Portable Windows build status: **not produced in this environment** because PyInstaller is not installed and PowerShell is unavailable.

## Commands run

```bash
python -m ruff check app tests
pytest -q
python -m compileall app tests
```

```bash
tmp=$(mktemp -d); mkdir -p "$tmp/home" "$tmp/case_from_standardreport"; printf 'ReporterConnectivityError services.bit9.com\n' > "$tmp/case_from_standardreport/ReporterLog.log"; printf 'not a real pdf, filename only for detection\n' > "$tmp/case_from_standardreport/Broadcom StandardReport_60114450.pdf"; HOME="$tmp/home" PYTHONPATH=. python -m app.drop_target "$tmp/case_from_standardreport" > "$tmp/stdout.txt"; cat "$tmp/stdout.txt"; echo "--- reports ---"; out=$(awk -F': ' '/^Output folder: / {print $2; exit}' "$tmp/stdout.txt"); find "$out" -maxdepth 1 -type f -printf '%f\n' | sort; echo "--- checklist ---"; sed -n '1,30p' "$out/missing_evidence_checklist.txt"
```

```bash
tmp=$(mktemp -d); mkdir -p "$tmp/home" "$tmp/60114450"; printf 'Execution Timeout Expired AntibodyMetadataLookup\n' > "$tmp/60114450/server.log"; HOME="$tmp/home" PYTHONPATH=. python -m app.drop_target "$tmp/60114450" --output "$tmp/custom output" > "$tmp/stdout.txt"; cat "$tmp/stdout.txt"; test -f "$tmp/custom output/triage_report.html" && echo CUSTOM_REPORT_EXISTS; test ! -d "$tmp/home/Desktop/TDSYNNEX-CB-LogParser" && echo NO_DESKTOP_OUTPUT_CREATED
```

```bash
pytest -q tests/integration/test_drop_mode_validation.py::test_large_streaming_chunked_and_limited_artifacts_use_desktop_case_output tests/unit/test_drop_target.py::test_run_scan_writes_partial_reports_on_fatal_pipeline_error
```

```bash
python -m PyInstaller --clean --noconfirm packaging/pyinstaller/drop_target.spec
```

```bash
if command -v pwsh >/dev/null 2>&1; then pwsh -NoProfile -ExecutionPolicy Bypass -File ./build-portable.ps1 -SkipTests; elif command -v powershell.exe >/dev/null 2>&1; then powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./build-portable.ps1 -SkipTests; else echo 'PowerShell is not installed in this Linux environment; cannot run build-portable.ps1.'; exit 127; fi
```

```bash
tmp=$(mktemp -d); mkdir -p "$tmp/home" "$tmp/60114450"; printf 'Execution Timeout Expired AntibodyMetadataLookup\nReporterConnectivityError services.bit9.com\n' > "$tmp/60114450/ReporterLog.log"; HOME="$tmp/home" PYTHONPATH=. python -m app.drop_target "$tmp/60114450" > "$tmp/stdout.txt"; out=$(awk -F': ' '/^Output folder: / {print $2; exit}' "$tmp/stdout.txt"); if rg -i 'confirmed root cause' "$out"; then echo UNEXPECTED_CONFIRMED_ROOT_CAUSE; exit 1; else echo NO_CONFIRMED_ROOT_CAUSE; fi; rg 'KB candidate' "$out/triage_report.txt" "$out/all_hits.csv" | head -5; echo "$out"
```

```bash
if [ -d dist/TDSYNNEX-CB-LogParser ]; then find dist/TDSYNNEX-CB-LogParser -maxdepth 2 -print | sort | sed -n '1,80p'; else echo 'dist/TDSYNNEX-CB-LogParser not present'; fi; if [ -f dist/TDSYNNEX-CB-LogParser-portable.zip ]; then echo ZIP_EXISTS; else echo 'dist/TDSYNNEX-CB-LogParser-portable.zip not present'; fi
```

## Test and validation results

| # | Criterion | Result | Evidence |
|---:|---|---|---|
| 1 | Portable build works without manual copying. | **Blocked** | `build-portable.ps1` could not run because PowerShell is not installed in this Linux environment. Static packaging tests passed in `pytest -q`. |
| 2 | EXE is in parent dist folder. | **Blocked** | `python -m PyInstaller --clean --noconfirm packaging/pyinstaller/drop_target.spec` failed with `No module named PyInstaller`, so `dist/TDSYNNEX-CB-LogParser` was not created. |
| 3 | `DROP-CUSTOMER-LOGS-HERE.bat` works. | **Blocked for built EXE** | Windows BAT execution was not possible in this Linux container. Static BAT checks passed in `pytest -q`. |
| 4 | Drag/drop input goes to Desktop case folder. | **Pass (source CLI)** | Source CLI output used `/tmp/.../home/Desktop/TDSYNNEX-CB-LogParser/Case-60114450-scan-20260506-181020`. |
| 5 | Case number is detected from folder name and StandardReport filename. | **Pass (source CLI/tests)** | Source CLI printed `Detected case number: 60114450` for a folder containing `Broadcom StandardReport_60114450.pdf`; pytest also covers folder-name detection. |
| 6 | `--output` overrides default Desktop behavior. | **Pass (source CLI)** | Custom output run wrote to `/tmp/.../custom output` and printed `NO_DESKTOP_OUTPUT_CREATED`. |
| 7 | Large files are streamed, not skipped. | **Pass (tests)** | Targeted large streaming acceptance test passed; it asserts no coverage row contains `File exceeds max_single_file_bytes`. |
| 8 | Zero-byte `trace.bt9` is reported as present but empty. | **Pass (tests)** | Targeted large streaming acceptance test passed and asserts `trace.bt9 present but empty` in `missing_evidence_checklist.txt`. |
| 9 | Reports are always generated. | **Pass (tests/source CLI)** | `pytest -q` passed, and source CLI runs generated all required reports including `scan_summary.txt`. |
| 10 | `scan_error.txt` is written on fatal exceptions. | **Pass (tests)** | `test_run_scan_writes_partial_reports_on_fatal_pipeline_error` passed. |
| 11 | `artifact_coverage.csv` lists every file. | **Pass (tests/source CLI)** | Large acceptance test asserts expected source, decoded, archive, PML, DMP, ETL, zero-byte, and binary artifacts appear in coverage. |
| 12 | `triage_report.html` is readable and not flooded. | **Pass (tests)** | Large acceptance test asserts `APPC_SQL_TIMEOUT` examples are capped to 25 or fewer in HTML. |
| 13 | Generic hits do not dominate main findings. | **Pass (tests)** | `pytest -q` covers generic-hit filtering/noise reduction and confirms generic hits do not flood the main triage report. |
| 14 | No report claims confirmed root cause. | **Pass (source CLI/tests)** | Source CLI report check printed `NO_CONFIRMED_ROOT_CAUSE`; pytest also checks this. |
| 15 | KBs are labeled as KB candidates. | **Pass (source CLI/tests)** | Source CLI report check found `KB candidate` labels in `triage_report.txt`; pytest also covers KB candidate wording. |
| 16 | Build portable ZIP. | **Blocked** | `dist/TDSYNNEX-CB-LogParser-portable.zip` was not created because PyInstaller and PowerShell are unavailable. |
| 17 | Run built EXE against synthetic case. | **Blocked** | No built EXE exists in this environment. The source CLI synthetic validation passed. |
| 18 | Run built EXE against a real App Control case folder if available. | **Blocked / not available** | No real App Control case folder was found in the workspace; only test fixtures are present. |

## Output folder examples

Source CLI StandardReport filename/case detection run:

```text
/tmp/tmp.rBiqD20V4O/home/Desktop/TDSYNNEX-CB-LogParser/Case-60114450-scan-20260506-181020
```

Source CLI root-cause/KB label validation run:

```text
/tmp/tmp.mj5YnZboyA/home/Desktop/TDSYNNEX-CB-LogParser/Case-60114450-scan-20260506-181109
```

Expected Windows engineer output path:

```text
Desktop\TDSYNNEX-CB-LogParser\Case-<CASE>-scan-<timestamp>\triage_report.html
```

Expected portable ZIP path after a successful Windows packaging run:

```text
dist\TDSYNNEX-CB-LogParser-portable.zip
```

Actual portable ZIP path in this validation environment:

```text
not created
```

## Known limitations

- PyInstaller is not installed in this Linux container, and `python -m pip install pyinstaller` is blocked by a package index proxy `403 Forbidden` response.
- PowerShell (`pwsh`/`powershell.exe`) is not installed, so `build-portable.ps1` cannot be executed here.
- The Windows BAT handoff and built EXE drag/drop flow require a Windows validation machine or the GitHub Actions Windows workflow.
- No real App Control customer case folder is present in the workspace; validation used synthetic cases and test fixtures only.
- Optional decoders are best-effort. When `tracerpt`, ProcMon, tshark, or other external tools are unavailable, the parser records limitations and falls back to metadata or binary string scanning where applicable.

## Final engineer instructions

1. Unzip portable ZIP.
2. Drag customer case folder or ZIP onto `DROP-CUSTOMER-LOGS-HERE.bat`.
3. Open:

```text
Desktop\TDSYNNEX-CB-LogParser\Case-<CASE>-scan-<timestamp>\triage_report.html
```

## Final portable ZIP location

No final portable ZIP was produced in this Linux validation environment.

When run successfully on Windows, the expected final portable ZIP location is:

```text
dist\TDSYNNEX-CB-LogParser-portable.zip
```
