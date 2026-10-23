"""Scope enforcement and SSRF protection (spec section 9).

Default posture: only http(s) URLs whose hostname is inside the approved scope
and which resolve exclusively to public IPs are fetchable. Localhost, private,
link-local, reserved and cloud-metadata destinations are rejected.

`allow_private` exists ONLY for the local test harness (intentionally
vulnerable fixtures on 127.0.0.1). It is a constructor parameter of the guard,
never exposed through the web UI or scan API, so users cannot turn it into a
production bypass.
"""
from __future__ import annotations
import ipaddress, socket
from urllib.parse import urlparse, urljoin

METADATA_IPS = {"169.254.169.254", "100.100.100.200"}

class ScopeError(Exception):
    pass

def normalize_target(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        raise ScopeError("empty target")
    if "://" not in raw:
        raw = "https://" + raw
    p = urlparse(raw)
    if p.scheme not in ("http", "https"):
        raise ScopeError(f"unsupported scheme: {p.scheme!r}")
    if not p.hostname:
        raise ScopeError("missing hostname")
    host = p.hostname.lower()
    port = p.port or (443 if p.scheme == "https" else 80)
    return f"{p.scheme}://{host}:{port}"

def _ip_allowed(ip_str: str, allow_private: bool) -> bool:
    if ip_str in METADATA_IPS:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if allow_private:
        return True
    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved \
       or ip.is_multicast or ip.is_unspecified:
        return False
    return True

def resolve_host(host: str):
    """Resolve A/AAAA records. Returns list of IP strings (may be empty)."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return []
    return sorted({i[4][0] for i in infos})

class ScopeGuard:
    def __init__(self, target: str, extra_hosts=None, allow_private: bool=False,
                 max_redirects: int = 5):
        self.base = normalize_target(target)
        p = urlparse(self.base)
        self.base_host = p.hostname
        self.base_port = p.port
        self.allow_private = allow_private
        self.max_redirects = max_redirects
        self.allowed_hosts = {self.base_host} | {h.lower() for h in (extra_hosts or [])}

    def resolve_validated(self, host: str):
        """Resolve host and return ONLY validated IPs. Raises ScopeError."""
        ips = resolve_host(host)
        if not ips:
            raise ScopeError(f"host {host!r} does not resolve")
        for ip in ips:
            if not _ip_allowed(ip, self.allow_private):
                raise ScopeError(f"host {host!r} resolves to prohibited address {ip}")
        return ips

    def check_url(self, url: str):
        """Validate a URL against scheme, host scope and resolved IPs.
        Returns (normalized_url, validated_ips). Raises ScopeError on violation."""
        abs_url = urljoin(self.base + "/", url)
        p = urlparse(abs_url)
        if p.scheme not in ("http", "https"):
            raise ScopeError(f"scheme {p.scheme!r} not allowed")
        host = (p.hostname or "").lower()
        if not host:
            raise ScopeError("empty host")
        if host not in self.allowed_hosts and not host.endswith("." + self.base_host):
            raise ScopeError(f"host {host!r} outside approved scope")
        ips = self.resolve_validated(host)
        return abs_url, ips

    def check_redirect(self, from_url: str, location: str, hop: int):
        if hop >= self.max_redirects:
            raise ScopeError("redirect limit exceeded")
        return self.check_url(urljoin(from_url, location))
