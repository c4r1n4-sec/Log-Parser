# AWS Windows VM script-portable usage

Use the script-portable runner when an AWS Windows diagnostic VM should run the
Carbon Black log parser from source files instead of the PyInstaller EXE. This is
useful for short-lived support VMs where Python is available or can be installed
quickly and where GUI dependencies are not needed.

## Prerequisites

- Windows Server or Windows desktop running in AWS.
- Python 3.11 preferred. The runner checks for Python in this order:
  1. `py -3.11`
  2. `py -3`
  3. `python`
- Internet access, or another approved method, for `pip` to install packages from
  `requirements-cli.txt`.

## Run the parser

1. Download the `TDSYNNEX-CB-LogParser-script-portable` workflow artifact and
   extract it to a writable folder on the VM, such as the Desktop.
2. Copy customer logs, ZIPs, PDFs, screenshots, or folders to the VM.
3. Drag one or more artifacts onto `RUN-CB-LOG-PARSER.bat`, or open Command
   Prompt in the extracted folder and run:

   ```bat
   RUN-CB-LOG-PARSER.bat C:\Path\To\CustomerLogs
   ```

The BAT creates a local `.venv`, installs `requirements-cli.txt`, and launches:

```bat
.venv\Scripts\python.exe -m app.drop_target --open-output --pause %*
```

Reports are written to the user's Desktop under
`TDSYNNEX-CB-LogParser\Case-<case-number>-scan-YYYYMMDD-HHMMSS`. The output
folder opens automatically when the scan completes.

## Notes for diagnostic VMs

- The script-portable runner does not use `TDSYNNEX-CB-LogParser.exe`.
- `requirements-cli.txt` intentionally omits PySide6 because the runner uses the
  command-line drop target, not the desktop GUI.
- Keep customer artifacts and generated reports on approved encrypted storage.
- Delete the extracted tool folder, `.venv`, customer artifacts, and generated
  reports before terminating or handing off the VM unless retention is required.
