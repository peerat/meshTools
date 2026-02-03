@echo off
setlocal

rem Build meshTalk.exe using PyInstaller on Windows.
rem Requires: Python 3.9+ and pip.

python -m pip install --upgrade pip
python -m pip install pyinstaller
python -m pip install -r requirements.txt

pyinstaller --onefile --name meshTalk meshTalk.py

echo.
echo Done. Output: dist\meshTalk.exe
endlocal
