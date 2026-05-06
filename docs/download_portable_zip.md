# Download the Portable Drag/Drop ZIP

Do **not** use GitHub's **Code > Download ZIP** button for engineer handoff.
That button always downloads the source repository and will not contain the
built `TDSYNNEX-CB-LogParser.exe`.

## Exact artifact to download

Download the portable tool from the GitHub Actions workflow artifact:

```text
Actions > Build Windows Portable Drag/Drop ZIP > latest successful run > Artifacts > TDSYNNEX-CB-LogParser-portable
```

The artifact contains:

```text
dist/TDSYNNEX-CB-LogParser-portable.zip
```

After extracting `TDSYNNEX-CB-LogParser-portable.zip`, the portable folder is:

```text
dist/TDSYNNEX-CB-LogParser/
  TDSYNNEX-CB-LogParser.exe
  DROP-CUSTOMER-LOGS-HERE.bat
  README-DROP-MODE.txt
  rules/
  templates/
  config/
  tools/
```

## Engineer use

1. Unzip `TDSYNNEX-CB-LogParser-portable.zip` to a writable local folder.
2. Drag customer ZIPs, PDFs, logs, screenshots, or folders onto
   `DROP-CUSTOMER-LOGS-HERE.bat`.
3. Wait for the scan to complete.
4. Open `triage_report.html` in the generated output folder.

The portable ZIP is a PyInstaller one-folder build. It does not require Python on
the engineer machine, does not require administrator rights, and does not create
an MSI, `setup.exe`, or installer.

## Local build fallback

If you are on a Windows packaging machine and need to build the artifact locally,
run:

```powershell
.\build-portable.ps1
```

The local build writes the same ZIP to:

```text
dist\TDSYNNEX-CB-LogParser-portable.zip
```
