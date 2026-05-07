@echo off
setlocal

echo TDSYNNEX Carbon Black Log Parser
echo Script portable mode
echo Reports will be written to your Desktop under TDSYNNEX-CB-LogParser.
echo.

if "%~1"=="" (
    echo Drag and drop customer case ZIPs, log folders, PDFs, or other artifacts onto RUN-CB-LOG-PARSER.bat.
    echo You can drop one or more files/folders at the same time.
    pause
    exit /b 1
)

set "BAT_DIR=%~dp0"
pushd "%BAT_DIR%" >nul || exit /b 1

set "PY_CMD="
py -3.11 --version >nul 2>nul && set "PY_CMD=py -3.11"
if not defined PY_CMD py -3 --version >nul 2>nul && set "PY_CMD=py -3"
if not defined PY_CMD python --version >nul 2>nul && set "PY_CMD=python"

if not defined PY_CMD (
    echo Python was not found. Install Python 3.11 in this Windows VM image, then try again.
    pause
    popd >nul
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo Creating local Python virtual environment...
    %PY_CMD% -m venv .venv
    if errorlevel 1 (
        echo Failed to create .venv with %PY_CMD%.
        pause
        popd >nul
        exit /b 1
    )
)

echo Installing script portable requirements...
".venv\Scripts\python.exe" -m pip install -r requirements-cli.txt
if errorlevel 1 (
    echo Failed to install requirements-cli.txt.
    pause
    popd >nul
    exit /b 1
)

".venv\Scripts\python.exe" -m app.drop_target --open-output --pause %*
set "EXIT_CODE=%ERRORLEVEL%"
popd >nul
exit /b %EXIT_CODE%
