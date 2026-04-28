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

py -3 -m PyInstaller --onefile --windowed --name meshTalk ^
  --collect-submodules PySide6.QtCore ^
  --collect-submodules PySide6.QtGui ^
  --collect-submodules PySide6.QtWidgets ^
  --exclude-module PySide6.Qt3DAnimation ^
  --exclude-module PySide6.Qt3DCore ^
  --exclude-module PySide6.Qt3DExtras ^
  --exclude-module PySide6.Qt3DInput ^
  --exclude-module PySide6.Qt3DLogic ^
  --exclude-module PySide6.Qt3DRender ^
  --exclude-module PySide6.QtBluetooth ^
  --exclude-module PySide6.QtCharts ^
  --exclude-module PySide6.QtDataVisualization ^
  --exclude-module PySide6.QtLocation ^
  --exclude-module PySide6.QtMultimedia ^
  --exclude-module PySide6.QtMultimediaWidgets ^
  --exclude-module PySide6.QtNetwork ^
  --exclude-module PySide6.QtNfc ^
  --exclude-module PySide6.QtOpenGL ^
  --exclude-module PySide6.QtOpenGLWidgets ^
  --exclude-module PySide6.QtPositioning ^
  --exclude-module PySide6.QtPrintSupport ^
  --exclude-module PySide6.QtQml ^
  --exclude-module PySide6.QtQuick ^
  --exclude-module PySide6.QtQuickControls2 ^
  --exclude-module PySide6.QtQuickWidgets ^
  --exclude-module PySide6.QtRemoteObjects ^
  --exclude-module PySide6.QtScxml ^
  --exclude-module PySide6.QtSensors ^
  --exclude-module PySide6.QtSerialPort ^
  --exclude-module PySide6.QtSql ^
  --exclude-module PySide6.QtSvg ^
  --exclude-module PySide6.QtSvgWidgets ^
  --exclude-module PySide6.QtTextToSpeech ^
  --exclude-module PySide6.QtWebChannel ^
  --exclude-module PySide6.QtWebEngineCore ^
  --exclude-module PySide6.QtWebEngineWidgets ^
  --exclude-module PySide6.QtWebEngine ^
  --exclude-module PySide6.QtWebSockets ^
  --exclude-module PySide6.QtXml ^
  --exclude-module PySide6.QtXmlPatterns ^
  meshTalk.py
if errorlevel 1 exit /b 1

echo.
echo Done. Output: dist\meshTalk.exe
endlocal
