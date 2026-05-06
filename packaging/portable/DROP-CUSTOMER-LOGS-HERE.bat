@echo off
setlocal
set "APP_DIR=%~dp0"
"%APP_DIR%TDSYNNEX-CB-LogParser.exe" --pause %*
exit /b %ERRORLEVEL%
