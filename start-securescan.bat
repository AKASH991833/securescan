@echo off
setlocal
cd /d "%~dp0"
if not exist .venv (
  echo Please run setup-securescan.bat once first.
  pause
  exit /b 1
)
if defined SECURESCAN_AI_KEY (
  echo AI explainer: real AI is enabled for this session.
) else (
  echo AI explainer: no key set, using the built-in local explainer ^(labeled, not AI^).
)
echo.
echo SecureScan is starting. Your browser will open http://127.0.0.1:5001
echo Keep this black window open while you use SecureScan. Close it to stop.
start "" "http://127.0.0.1:5001"
.venv\Scripts\python.exe -m securescan.webapp
pause
