@echo off
setlocal

set "BAT_DIR=%~dp0"
cd /d "%BAT_DIR%"

echo TDSYNNEX Carbon Black Log Parser - script portable runner
echo.

set "PYTHON_LAUNCHER="
py -3.11 --version >nul 2>&1
if not errorlevel 1 set "PYTHON_LAUNCHER=py -3.11"

if not defined PYTHON_LAUNCHER (
    py -3 --version >nul 2>&1
    if not errorlevel 1 set "PYTHON_LAUNCHER=py -3"
)

if not defined PYTHON_LAUNCHER (
    python --version >nul 2>&1
    if not errorlevel 1 set "PYTHON_LAUNCHER=python"
)

if not defined PYTHON_LAUNCHER (
    echo ERROR: Python 3.11 or another Python 3 installation was not found.
    echo Install Python from https://www.python.org/downloads/windows/ and try again.
    pause
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo Creating local Python virtual environment in .venv ...
    %PYTHON_LAUNCHER% -m venv .venv
    if errorlevel 1 (
        echo ERROR: Failed to create .venv.
        pause
        exit /b 1
    )
)

echo Installing command-line dependencies from requirements-cli.txt ...
".venv\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 (
    echo ERROR: Failed to upgrade pip in .venv.
    pause
    exit /b 1
)

".venv\Scripts\python.exe" -m pip install -r requirements-cli.txt
if errorlevel 1 (
    echo ERROR: Failed to install requirements-cli.txt.
    pause
    exit /b 1
)

".venv\Scripts\python.exe" -m app.drop_target --open-output --pause %*
set "EXIT_CODE=%ERRORLEVEL%"
exit /b %EXIT_CODE%
