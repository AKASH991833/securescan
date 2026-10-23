@echo off
setlocal
cd /d "%~dp0"
echo === SecureScan one-time setup ===
echo.

set PY=
where py >nul 2>nul
if not errorlevel 1 set PY=py
if not defined PY (
  where python >nul 2>nul
  if not errorlevel 1 set PY=python
)
if not defined PY (
  echo Python was not found on this PC.
  echo.
  echo Install it once, then double-click this file again:
  echo   1. Go to https://www.python.org/downloads/
  echo   2. Download Python 3.10 or newer for Windows.
  echo   3. Run the installer and TICK the box "Add python.exe to PATH".
  echo   4. Finish the installer, then double-click setup-securescan.bat again.
  echo.
  pause
  exit /b 1
)
echo Found Python:
%PY% --version
echo.

if not exist .venv (
  echo Creating an isolated environment for SecureScan...
  %PY% -m venv .venv
  if errorlevel 1 (
    echo Could not create the environment. Send a photo of this window to Instinct.
    pause
    exit /b 1
  )
)

echo Installing SecureScan dependencies - one time only...
.venv\Scripts\python.exe -m pip install --upgrade pip --quiet
.venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 (
  echo Dependency install failed. Check your internet connection and run this file again.
  pause
  exit /b 1
)

echo.
echo Setup complete. From now on, just double-click start-securescan.bat
pause
