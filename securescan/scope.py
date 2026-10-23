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
    """Exact authorized scope: (scheme, host, port) triples. The approved
    scope is the normalized target's triple plus any explicitly added triples.
    Subdomains and sibling ports are NOT included unless explicitly approved.
    An http->https upgrade redirect on the SAME host is permitted (standard
    HTTPS enforcement), nothing else crosses scheme boundaries."""

    def __init__(self, target: str, extra_hosts=None, allow_private: bool=False,
                 max_redirects: int = 5):
        self.base = normalize_target(target)
        p = urlparse(self.base)
        self.base_host = p.hostname
        self.base_port = p.port
        self.base_scheme = p.scheme
        self.allow_private = allow_private
        self.max_redirects = max_redirects
        self.allowed_triples = {(p.scheme, p.hostname, p.port)}
        for h in (extra_hosts or []):
            ep = urlparse(h if "://" in h else p.scheme + "://" + h)
            port = ep.port or (443 if ep.scheme == "https" else 80)
            self.allowed_triples.add((ep.scheme, (ep.hostname or "").lower(), port))

    def _triple_allowed(self, scheme, host, port) -> bool:
        if (scheme, host, port) in self.allowed_triples:
            return True
        # permit ONLY http->https upgrade on the same approved host
        for (s, h, p) in self.allowed_triples:
            if h == host and s == "http" and scheme == "https" and port == 443:
                return True
        return False

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
        port = p.port or (443 if p.scheme == "https" else 80)
        if not self._triple_allowed(p.scheme, host, port):
            raise ScopeError(
                f"(scheme={p.scheme}, host={host!r}, port={port}) outside approved scope")
        ips = self.resolve_validated(host)
        return abs_url, ips

    def check_redirect(self, from_url: str, location: str, hop: int):
        if hop >= self.max_redirects:
            raise ScopeError("redirect limit exceeded")
        return self.check_url(urljoin(from_url, location))
