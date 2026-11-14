@echo off
setlocal
title Shared-Files-Security
echo Starting Shared-Files-Security...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run.ps1" %*
set "appExitCode=%errorlevel%"
if not "%appExitCode%"=="0" (
    echo The application could not start or exited with an error. See the message above.
    set /p "closePrompt=Press Enter to close this window..."
)
exit /b %appExitCode%
