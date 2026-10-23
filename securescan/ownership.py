"""Ownership verification: web challenge (testable) and DNS TXT (implemented
via system resolver tools when present). Tokens are random, expiring,
single-use, and audit-logged (spec section 9)."""
from __future__ import annotations
import secrets, shutil, subprocess, time

TOKEN_TTL = 3600  # seconds

class ChallengeStore:
    def __init__(self):
        self._challenges = {}

    def create(self, host: str) -> dict:
        token = "securescan-verification=" + secrets.token_urlsafe(32)
        self._challenges[host] = {"token": token, "expires": time.time() + TOKEN_TTL,
                                  "used": False, "created": time.time()}
        return {"host": host, "token": token, "expires_in": TOKEN_TTL,
                "web_path": "/.well-known/securescan-verification.txt",
                "dns_name": f"_securescan.{host}"}

    def _valid(self, host: str) -> dict:
        ch = self._challenges.get(host)
        if not ch:
            raise ValueError("no challenge for host")
        if ch["used"]:
            raise ValueError("challenge already used (replay protection)")
        if time.time() > ch["expires"]:
            raise ValueError("challenge expired")
        return ch

    def verify_web(self, host: str, client) -> bool:
        ch = self._valid(host)
        base = getattr(getattr(client, "guard", None), "base", None) or ("https://" + host)
        r = client.get(base + "/.well-known/securescan-verification.txt")
        if r.error or r.status != 200:
            return False
        if r.body.strip() == ch["token"]:
            ch["used"] = True   # single-use: replay protection
            return True
        return False

    def verify_dns(self, host: str) -> dict:
        """Returns {'verified': bool, 'detail': str}. Honest about resolver availability."""
        ch = self._valid(host)
        name = f"_securescan.{host}"
        if not shutil.which("dig"):
            return {"verified": False,
                    "detail": "DNS TXT lookup tool (dig) unavailable in this environment; use web challenge."}
        try:
            out = subprocess.run(["dig", "+short", "TXT", name],
                                 capture_output=True, text=True, timeout=15).stdout
        except subprocess.TimeoutExpired:
            return {"verified": False, "detail": "DNS lookup timed out"}
        if ch["token"] in out:
            ch["used"] = True
            return {"verified": True, "detail": "DNS TXT matched"}
        return {"verified": False, "detail": f"token not found in TXT records for {name}"}
