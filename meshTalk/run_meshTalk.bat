@echo off
setlocal

rem Simple launcher for meshTalk.exe (non-blocking).

set "EXE=%~dp0dist\meshTalk.exe"
if not exist "%EXE%" (
  echo ERROR: %EXE% not found. Build first with build_meshTalk.bat
  pause
  exit /b 1
)

cd /d "%~dp0"
start "" "%EXE%"
if errorlevel 1 (
  echo ERROR: failed to start %EXE%
  pause
  exit /b 1
)

endlocal
