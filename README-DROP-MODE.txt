TDSYNNEX Carbon Black Log Parser - Drag/drop mode
==================================================

Quick use
---------
1. Unzip the portable package to a writable local folder.
2. Drag customer files or folders onto DROP-CUSTOMER-LOGS-HERE.bat.
   Supported inputs include customer ZIPs, PDFs, logs, folders, and screenshots.
3. By default, reports are written to your Desktop under a case-number folder:
   %USERPROFILE%\Desktop\TDSYNNEX-CB-LogParser\Case-60114450-scan-YYYYMMDD-HHMMSS
   If no Broadcom case number is detected, the folder uses Case-UNKNOWN.
4. When the scan finishes, open triage_report.html in the output folder.

Case-number output folders
--------------------------
Drag/drop mode detects 8-digit Broadcom case numbers that start with 6 from
input folder names, file names, and StandardReport PDF text when PDF text
extraction is available. Examples include folders named 60114450 and files such
as Broadcom StandardReport_60114450.pdf, StandardReport-60114450.pdf, and
Case_60114450.zip.

Use --output only when you want to choose a specific report folder. When
--output is provided, the Desktop case-number default is not used.

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
3. Drag a folder whose path contains spaces onto the BAT. Confirm it scans and
   writes reports under Desktop\TDSYNNEX-CB-LogParser\Case-<CASE_NUMBER>-scan-YYYYMMDD-HHMMSS.
4. Drag multiple files/folders onto the BAT. Confirm the console reports the
   number of inputs received and the final triage_report.html path.
