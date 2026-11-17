@echo off
rem Double-click or run "start.bat" to launch PhishGuard.
rem WHY this wrapper: Windows blocks .ps1 scripts by default (execution policy).
rem This runs start.ps1 with the policy relaxed for this one process only.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start.ps1" %*
