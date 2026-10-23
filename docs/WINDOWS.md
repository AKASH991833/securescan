# SecureScan on Windows (near-one-click)

Honesty label: these files were prepared and verified step-by-step on Linux
(the exact same Python commands). The two .bat files themselves have NOT been
executed on a real Windows machine yet - first run on your PC is the real
test. Anything unclear: send Instinct a photo of the window.

## What you need (once)
- Windows 10 or 11.
- Python 3.10 or newer from https://www.python.org/downloads/ -
  during install, TICK "Add python.exe to PATH".
- Internet access during setup only (downloads Python packages).

## Setup (once, about 3-5 minutes)
1. Put the SecureScan folder anywhere (e.g. Desktop).
2. Double-click `setup-securescan.bat`. It checks Python, creates an isolated
   environment inside the folder, and installs dependencies.

## Every day use
- Double-click `start-securescan.bat`. Your browser opens
  http://127.0.0.1:5001 - SecureScan runs only on YOUR PC (127.0.0.1 means
  "this computer"; nobody else can reach it). Keep the black window open
  while you use it; close the window to stop.

## Rules that protect you
- Only scan websites you OWN or are explicitly authorized to test. The app
  requires an ownership verification step before any scan.
- It cannot scan localhost/private addresses from the web UI.
- Reports label unconfirmed items as potential/hardening, never as proven
  vulnerabilities.

## Optional: real AI explanations
Without a key, finding explanations come from a built-in local template
(clearly labeled, NOT AI). To enable the real AI explainer:
1. Open https://aistudio.google.com/api-keys (your Google account), find the
   key named "SecureScan project key", and copy it.
2. Double-click `set-ai-key.bat`. A hidden prompt appears: paste the key
   (NOTHING shows while you paste - that is normal), press Enter, then paste
   it once more to confirm.
3. Close ALL SecureScan windows, then start start-securescan.bat again.
The key is stored encrypted for YOUR Windows user only (Windows DPAPI), at
%USERPROFILE%\.securescan\ai.key - OUTSIDE the SecureScan folder, never in
command history, never shown, never logged. It is sent only to Google's own
API when you run an explanation. To remove it: `python -m securescan.local_key clear`.

## If something fails
- "Python was not found": redo the Python install with the PATH box ticked.
- Dependency install failed: check internet, run setup again.
- Anything else: send Instinct a photo of the window; do not retry loops.
