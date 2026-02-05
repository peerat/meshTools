@echo off
setlocal

rem Simple launcher for meshTalk.exe (keeps window open).

set "EXE=%~dp0dist\meshTalk.exe"
if not exist "%EXE%" (
  echo ERROR: %EXE% not found. Build first with build_meshTalk.bat
  pause
  exit /b 1
)

"%EXE%"

echo.
pause
endlocal
