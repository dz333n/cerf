@echo off
REM Run cerf.exe with the given arguments
REM Usage: run.cmd [cerf options] <path-to-arm-wince-exe>
taskkill /f /im cerf.exe >nul 2>&1
timeout /t 1 /nobreak >nul
"%~dp0build\Release\x64\cerf.exe" %*
