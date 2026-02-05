@echo off
setlocal

rem Build meshTalk.exe using PyInstaller on Windows.
rem Requires: Python 3.9+ and pip.

where py >nul 2>nul
if errorlevel 1 (
  echo ERROR: Python launcher "py" not found. Install Python 3.9+ and enable it in PATH.
  exit /b 1
)

py -3 -m pip --version >nul 2>nul
if errorlevel 1 (
  echo ERROR: pip not available for Python 3. Install pip or reinstall Python.
  exit /b 1
)

py -3 -m pip install --upgrade pip
if errorlevel 1 exit /b 1

py -3 -m pip install pyinstaller
if errorlevel 1 exit /b 1

py -3 -m pip install PySide6
if errorlevel 1 exit /b 1

py -3 -m pip install -r requirements.txt
if errorlevel 1 exit /b 1

py -3 -m PyInstaller --onefile --name meshTalk --collect-all PySide6 meshTalk.py
if errorlevel 1 exit /b 1

echo.
echo Done. Output: dist\meshTalk.exe
endlocal
