"""Optional LOCAL storage for the user's own Gemini API key.

Goal: enable the real AI explainer without ever pasting the key into a
command line, chat, script, or file that ships with the project.

- The key is typed at a MASKED prompt (getpass: nothing echoes, nothing is
  logged) via `python -m securescan.local_key setup`.
- Storage lives OUTSIDE the project folder at ~/.securescan/ai.key so it can
  never be committed or packaged.
- On Windows the key is encrypted with DPAPI (CryptProtectData): only the
  same Windows user account can decrypt it. On other systems it is a plain
  file locked to the owner (dir 0700, file 0600) - weaker, documented.
- No value is ever printed, returned by CLI commands, or written to logs.
"""
from __future__ import annotations
import base64, getpass, os, stat, sys
from pathlib import Path

STORE_DIR = Path.home() / ".securescan"
STORE_FILE = STORE_DIR / "ai.key"

def _protect(data: bytes) -> bytes:
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes
        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]
        def blob(bs):
            buf = ctypes.create_string_buffer(bs, len(bs))
            return DATA_BLOB(len(bs), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf
        in_blob, _in_buf = blob(data)
        out_blob = DATA_BLOB()
        if not ctypes.windll.crypt32.CryptProtectData(
                ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
            raise OSError("CryptProtectData failed")
        try:
            return ctypes.string_at(out_blob.pbData, out_blob.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(out_blob.pbData)
    return data  # non-Windows: permissions are the protection (documented)

def _unprotect(data: bytes) -> bytes:
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes
        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]
        in_buf = ctypes.create_string_buffer(data, len(data))
        in_blob = DATA_BLOB(len(data), ctypes.cast(in_buf, ctypes.POINTER(ctypes.c_char)))
        out_blob = DATA_BLOB()
        if not ctypes.windll.crypt32.CryptUnprotectData(
                ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
            raise OSError("CryptUnprotectData failed")
        try:
            return ctypes.string_at(out_blob.pbData, out_blob.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(out_blob.pbData)
    return data

def store_key(key: str) -> None:
    """Validate lightly and store. Never prints or returns the key."""
    key = (key or "").strip()
    if len(key) < 20:
        raise ValueError("that does not look like an API key (too short)")
    STORE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(STORE_DIR, 0o700)
    payload = base64.b64encode(_protect(key.encode()))
    fd = os.open(STORE_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(payload)
    os.chmod(STORE_FILE, 0o600)

def load_key():
    """Return the stored key, or None. Silent on every failure by design."""
    try:
        raw = STORE_FILE.read_bytes()
        return _unprotect(base64.b64decode(raw)).decode() or None
    except Exception:
        return None

def clear_key() -> bool:
    try:
        STORE_FILE.unlink()
        return True
    except FileNotFoundError:
        return False

def key_present() -> bool:
    return STORE_FILE.is_file()

def main(argv=None):
    cmd = (argv or sys.argv[1:] or ["status"])[0]
    if cmd == "setup":
        k1 = getpass.getpass("Paste your Gemini API key (typing is hidden), then Enter: ")
        k2 = getpass.getpass("Paste it once more to confirm: ")
        if k1 != k2:
            print("The two entries did not match. Nothing was stored. Run setup again.")
            return 1
        try:
            store_key(k1)
        except ValueError as e:
            print(f"Not stored: {e}")
            return 1
        where = "encrypted for this Windows user (DPAPI)" if sys.platform == "win32" \
                else "locked to this user account (file permissions)"
        print(f"Stored. The key is {where} at {STORE_FILE}")
        print("It is outside the SecureScan folder and is never shown or logged.")
        return 0
    if cmd == "status":
        print("a local AI key is stored" if key_present() else "no local AI key stored")
        return 0
    if cmd == "clear":
        print("removed" if clear_key() else "no local AI key was stored")
        return 0
    print("usage: python -m securescan.local_key [setup|status|clear]")
    return 2

if __name__ == "__main__":
    sys.exit(main())
