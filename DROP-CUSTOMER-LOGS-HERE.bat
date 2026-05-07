@echo off
setlocal

echo TDSYNNEX Carbon Black Log Parser
echo Drag/drop mode
echo Reports will be written to your Desktop under TDSYNNEX-CB-LogParser.
echo.

set "BAT_DIR=%~dp0"
set "EXE=%BAT_DIR%TDSYNNEX-CB-LogParser.exe"

if not exist "%EXE%" (
    set "EXE=%BAT_DIR%dist\TDSYNNEX-CB-LogParser\TDSYNNEX-CB-LogParser.exe"
)

if not exist "%EXE%" (
    echo TDSYNNEX-CB-LogParser.exe was not found. This BAT must be in the same folder as the portable EXE.
    pause
    exit /b 1
)

if "%~1"=="" (
    echo Drag and drop customer logs, ZIPs, PDFs, folders, or screenshots onto this BAT file.
    pause
    exit /b 1
)

"%EXE%" --open-output --pause %*
exit /b %ERRORLEVEL%
