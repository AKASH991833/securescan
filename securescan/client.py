"""Budget-limited safe HTTP client with TRUE per-connection IP pinning.

How pinning works here: the ScopeGuard validates the hostname and returns the
exact IPs it screened. The client then opens the TCP socket to THAT IP itself
(stdlib socket/http.client), while the Host header, TLS SNI and certificate
verification all use the real hostname. No DNS resolution happens after
validation, and there is NO global resolver patching - each connection is
independently pinned, so concurrent scans cannot race.
"""
from __future__ import annotations
import http.client, socket, ssl, time
from urllib.parse import urlparse, urljoin
from .scope import ScopeGuard, ScopeError

MAX_BODY_BYTES = 1_000_000
DEFAULT_TIMEOUT = 10
DEFAULT_BUDGET = 60

class FetchResult:
    def __init__(self, url, status, headers, body, elapsed, error=None):
        self.url, self.status, self.headers = url, status, headers
        self.body, self.elapsed, self.error = body, elapsed, error

class SafeClient:
    def __init__(self, guard: ScopeGuard, budget: int = DEFAULT_BUDGET,
                 timeout: int = DEFAULT_TIMEOUT):
        self.guard, self.budget, self.timeout = guard, budget, timeout
        self.used = 0
        self.default_headers = {
            "User-Agent": "SecureScan/0.1 (authorized security audit)"}

    def _fetch_once(self, url: str, ips, extra_headers, read_body: bool = True) -> FetchResult:
        p = urlparse(url)
        host = p.hostname
        port = p.port or (443 if p.scheme == "https" else 80)
        path = p.path or "/"
        if p.query:
            path += "?" + p.query
        start = time.time()
        conn = None
        try:
            ip = ips[0]  # connect ONLY to a guard-validated IP
            raw = socket.create_connection((ip, port), timeout=self.timeout)
            if p.scheme == "https":
                ctx = ssl.create_default_context()   # full cert verification
                raw = ctx.wrap_socket(raw, server_hostname=host)  # SNI = real host
            conn = http.client.HTTPConnection(host, port, timeout=self.timeout)
            conn.sock = raw
            headers = dict(self.default_headers)
            headers.update(extra_headers or {})
            conn.request("GET", path, headers=headers)
            resp = conn.getresponse()
            if read_body:
                body = resp.read(MAX_BODY_BYTES + 1)[:MAX_BODY_BYTES]
            else:
                # Deliberately do NOT read the payload (e.g. potential secret
                # files): headers only, connection closed unread.
                body = b""
            hdrs = {}
            for k, v in resp.getheaders():
                hdrs[k] = v   # last-wins; Set-Cookie single-value checks only
            enc = "utf-8"
            ctype = hdrs.get("Content-Type", "")
            if "charset=" in ctype:
                enc = ctype.split("charset=")[-1].split(";")[0].strip()
            return FetchResult(url, resp.status, hdrs,
                               body.decode(enc, errors="replace"),
                               time.time() - start)
        except (socket.error, ssl.SSLError, http.client.HTTPException, OSError) as e:
            return FetchResult(url, 0, {}, "", time.time() - start,
                               error=f"network: {type(e).__name__}")
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def get(self, url: str, headers=None, allow_redirects=True,
            read_body: bool = True) -> FetchResult:
        try:
            url, ips = self.guard.check_url(url)
        except ScopeError as e:
            return FetchResult(url, 0, {}, "", 0.0, error=f"scope: {e}")
        if self.used >= self.budget:
            return FetchResult(url, 0, {}, "", 0.0, error="budget: request budget exceeded")
        self.used += 1
        start = time.time()
        result = self._fetch_once(url, ips, headers, read_body=read_body)
        hops = 0
        while (allow_redirects and result.status in (301, 302, 303, 307, 308)
               and "Location" in result.headers):
            try:
                nxt, nips = self.guard.check_url(
                    urljoin(result.url, result.headers["Location"]))
            except ScopeError as e:
                return FetchResult(result.url, 0, {}, "", time.time() - start,
                                   error=f"scope: {e}")
            hops += 1
            if hops > self.guard.max_redirects:
                return FetchResult(nxt, 0, {}, "", time.time() - start,
                                   error="scope: redirect limit exceeded")
            if self.used >= self.budget:
                return FetchResult(nxt, 0, {}, "", time.time() - start,
                                   error="budget: request budget exceeded")
            self.used += 1
            result = self._fetch_once(nxt, nips, headers, read_body=read_body)
        return result
