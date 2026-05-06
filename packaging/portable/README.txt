TDSYNNEX Carbon Black Log Parser - Portable Package
===================================================

This is a portable local-only tool. It is not an installer.

Run:
  TDSYNNEX-CB-LogParser.exe

No administrator rights are required. Python is not required on the target
engineer machine after packaging. The tool does not send telemetry, make
outbound network calls, install services, create scheduled tasks, or write
system registry keys.

Outputs are written to the selected output folder. If no folder is selected,
use the bundled output folder.

Optional helper tools may be copied under tools/ if approved for your portable
package. Missing helper tools do not stop scans; affected artifacts are recorded
with decoder limitations.

Drag-and-drop command-line mode:
- Drop customer logs, ZIPs, PDFs, or folders onto TDSYNNEX-CB-LogParser.exe.
- Or drop them onto DROP-CUSTOMER-LOGS-HERE.bat to keep the console open.
- Reports are written to Documents\TDSYNNEX-CB-LogParser\scan-YYYYMMDD-HHMMSS by default.

