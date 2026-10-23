@echo off
setlocal
cd /d "%~dp0"
if not exist .venv (
  echo Please run setup-securescan.bat once first.
  pause
  exit /b 1
)
echo You are about to store your Gemini API key on THIS PC only.
echo Typing is hidden. The key is stored encrypted for your Windows user
echo ^(DPAPI^), outside this folder, and is never shown or logged.
echo.
.venv\Scripts\python.exe -m securescan.local_key setup
pause
