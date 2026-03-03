@echo off
REM Build Release x64 and run cerf.exe with the given arguments
REM Usage: build_and_run.cmd [cerf options] <path-to-arm-wince-exe>
taskkill /f /im cerf.exe >nul 2>&1
timeout /t 1 /nobreak >nul

echo Building...
"C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" "%~dp0cerf.sln" /p:Configuration=Release /p:Platform=x64 /v:minimal
if errorlevel 1 (
    echo Build failed!
    exit /b 1
)

echo Running...
"%~dp0build\Release\x64\cerf.exe" %*
