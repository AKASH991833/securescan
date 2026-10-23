"""Ownership verification: web challenge (testable) and DNS TXT (implemented
via system resolver tools when present). Tokens are random, expiring,
single-use, and audit-logged (spec section 9)."""
from __future__ import annotations
import secrets, time

TOKEN_TTL = 3600  # seconds

class ChallengeStore:
    def __init__(self):
        self._challenges = {}

    def _key(self, host: str, org_id: str = None):
        # challenges are tenant-scoped: one org's challenge/verification never
        # authorizes another org's scan of the same host
        return (org_id or "local", host)

    def create(self, host: str, org_id: str = None) -> dict:
        token = "securescan-verification=" + secrets.token_urlsafe(32)
        self._challenges[self._key(host, org_id)] = {
            "token": token, "expires": time.time() + TOKEN_TTL,
            "used": False, "created": time.time()}
        return {"host": host, "token": token, "expires_in": TOKEN_TTL,
                "web_path": "/.well-known/securescan-verification.txt",
                "dns_name": f"_securescan.{host}"}

    def _valid(self, host: str, org_id: str = None) -> dict:
        ch = self._challenges.get(self._key(host, org_id))
        if not ch:
            raise ValueError("no challenge for host")
        if ch["used"]:
            raise ValueError("challenge already used (replay protection)")
        if time.time() > ch["expires"]:
            raise ValueError("challenge expired")
        return ch

    def verify_web(self, host: str, client, org_id: str = None) -> bool:
        ch = self._valid(host, org_id)
        base = getattr(getattr(client, "guard", None), "base", None) or ("https://" + host)
        r = client.get(base + "/.well-known/securescan-verification.txt")
        if r.error or r.status != 200:
            return False
        if r.body.strip() == ch["token"]:
            ch["used"] = True   # single-use: replay protection
            return True
        return False

    def verify_dns(self, host: str, resolver=None, org_id: str = None) -> dict:
        """Returns {'verified': bool, 'detail': str}. Uses dnspython (pure
        Python, free); no external dig dependency. `resolver` is injectable
        for tests. Honest about lookup failures."""
        try:
            ch = self._valid(host, org_id)
        except ValueError as e:
            return {"verified": False, "detail": str(e)}
        name = f"_securescan.{host}"
        try:
            import dns.resolver
        except ImportError:
            return {"verified": False,
                    "detail": "dnspython not installed; use web challenge."}
        r = resolver or dns.resolver.Resolver()
        try:
            answers = r.resolve(name, "TXT", lifetime=10)
        except Exception as e:
            return {"verified": False,
                    "detail": f"TXT lookup for {name} failed: {type(e).__name__}"}
        txts = [b"".join(a.strings).decode("utf-8", "replace") for a in answers]
        if ch["token"] in txts:
            ch["used"] = True
            return {"verified": True, "detail": "DNS TXT matched"}
        return {"verified": False,
                "detail": f"token not found in {len(txts)} TXT record(s) for {name}"}
