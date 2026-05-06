TDSYNNEX Carbon Black Log Parser - Drag/drop mode
==================================================

Quick use
---------
1. Unzip the portable package to a writable local folder.
2. Drag customer files or folders onto DROP-CUSTOMER-LOGS-HERE.bat.
   Supported inputs include customer ZIPs, PDFs, logs, folders, and screenshots.
3. The tool creates output under Desktop\TDSYNNEX-CB-LogParser\Case-<CASE_NUMBER>-scan-YYYYMMDD-HHMMSS by default.
4. When the scan finishes, open triage_report.html in the output folder.

Local-only notes
----------------
- This is local-only processing.
- No logs are uploaded.
- No installer is used.
- Administrator rights are not required.
- The BAT does not write to the registry and does not install anything.
- KBs are candidates only.
- The tool does not prove root cause automatically.

Manual BAT test steps
---------------------
1. Place DROP-CUSTOMER-LOGS-HERE.bat in the same folder as
   TDSYNNEX-CB-LogParser.exe, or leave it at the repository root after building
   dist\TDSYNNEX-CB-LogParser\TDSYNNEX-CB-LogParser.exe.
2. Double-click the BAT with no dropped files. Confirm it prints:
   "Drag and drop customer logs, ZIPs, PDFs, folders, or screenshots onto this BAT file."
   Then confirm it pauses and exits after a keypress.
3. Drag a folder whose path contains spaces onto the BAT. Confirm the console
   shows the TDSYNNEX banner, the EXE starts with --open-output --pause, and the
   scan receives the path correctly.
4. Drag multiple files/folders onto the BAT. Confirm all dropped paths are passed
   through and triage_report.html is created in Desktop\TDSYNNEX-CB-LogParser under a case-specific folder.
5. Temporarily move or rename the EXE and run the BAT. Confirm it prints:
   "TDSYNNEX-CB-LogParser.exe was not found. This BAT must be in the same folder as the portable EXE."
   Then confirm it pauses and exits with code 1.
