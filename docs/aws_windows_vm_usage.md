# AWS Windows 11 Diagnostic VM Script Portable Usage

Use the script portable package on AWS Windows 11 diagnostic VMs when the unsigned PyInstaller EXE is blocked by Smart App Control or SmartScreen.

## Why this mode exists

Smart App Control may block unsigned EXEs and has no per-app allowlist. The script portable runner avoids launching `TDSYNNEX-CB-LogParser.exe`; it runs the same drop-target workflow with Python instead.

Keep Defender enabled on diagnostic VMs. Do not disable Microsoft Defender to run this tool.

## VM image prerequisite

Python 3.11 should be installed in the VM image. The runner looks for Python in this order:

1. `py -3.11`
2. `py -3`
3. `python`

On first run, `RUN-CB-LOG-PARSER.bat` creates a local `.venv` beside the BAT file and installs the script-mode requirements from `requirements-cli.txt`.

## Run a customer case

1. Download and unzip the `TDSYNNEX-CB-LogParser-script-portable` artifact.
2. Keep the unzipped folder together; do not move `app`, `rules`, `templates`, `config`, or `tools` away from the BAT file.
3. Drag case ZIPs/folders onto `RUN-CB-LOG-PARSER.bat`.
4. Wait for the scan to finish and review any console warnings.

Reports are written to:

```text
Desktop\TDSYNNEX-CB-LogParser\Case-<case>-scan-<timestamp>
```

Open `triage_report.html` from that output folder for the summary report. CSV details are in the same scan folder.
