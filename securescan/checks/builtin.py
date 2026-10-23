"""Built-in passive / non-destructive checks (spec section 7 B, C).

Honesty rules baked in:
- A missing header is a hardening gap (status=potential), never a confirmed vuln.
- Anything requiring exploitation proof is reported as inconclusive/potential
  with preconditions stated.
"""
from __future__ import annotations
import re, ssl, socket, datetime
from dataclasses import dataclass
from urllib.parse import urlparse
from ..findings import Finding, STATUS_CONFIRMED, STATUS_POTENTIAL, STATUS_INCONCLUSIVE

@dataclass
class Check:
    id: str
    title: str
    category: str
    fn: object
    profiles: tuple = (1, 2)   # profiles this check belongs to

def _f(check, sev, status, conf, asset, **kw):
    return Finding(check_id=check.id, title=check.title, category=check.category,
                   severity=sev, status=status, confidence=conf, asset=asset, **kw)

def https_enforcement(ctx):
    c, out = CHECK_BY_ID["https-enforcement"], []
    http_url = "http://" + ctx.guard.base_host + ":" + str(
        80 if ctx.guard.base_port in (80, 443) else ctx.guard.base_port)
    r = ctx.client.get(http_url, allow_redirects=False)
    if r.error:
        out.append(_f(c, "info", STATUS_INCONCLUSIVE, "low", http_url,
                      description="Could not fetch the plain-HTTP endpoint.",
                      evidence=r.error,
                      preconditions="HTTP port reachable from scanner"))
    elif r.status in (301, 302, 307, 308) and r.headers.get("location", "").lower().startswith("https"):
        out.append(_f(c, "info", "not-detected", "high", http_url,
                      description=f"HTTP redirects to HTTPS ({r.status})."))
    else:
        out.append(_f(c, "medium", STATUS_CONFIRMED, "high", http_url,
                      description="Plain HTTP endpoint does not redirect to HTTPS.",
                      evidence=f"GET {http_url} -> {r.status}",
                      impact="Users reaching the site over HTTP can have traffic observed or modified in transit.",
                      remediation="Redirect all HTTP traffic to HTTPS and enable HSTS.",
                      cwe="CWE-319", owasp="A02:2021"))
    return out

def _pinned_tls_connect(ctx, host, port, make_context):
    """One TLS connection pinned to a guard-validated IP.

    The ScopeGuard re-validates and returns ONLY the IPs it screened; the TCP
    socket goes to that IP while SNI and certificate hostname verification use
    the real hostname. No DNS resolution happens here (same invariant as
    SafeClient); a subprocess-free replacement for what testssl would do
    unpinned. Raises ScopeError if the (scheme, host, port) triple is outside
    the approved scope.
    """
    _, ips = ctx.guard.check_url(f"https://{host}:{port}/")
    raw = socket.create_connection((ips[0], port), timeout=10)
    try:
        context = make_context()
        return context.wrap_socket(raw, server_hostname=host)
    except Exception:
        raw.close()
        raise

def _deprecated_tls_accepted(ctx, host, port, version):
    """True if the server completes a handshake at a deprecated TLS version.
    Pinned to the validated IP exactly like the main handshake; verifies
    protocol acceptance only (certificate checks are the main check's job)."""
    def make():
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        c.minimum_version = version
        c.maximum_version = version
        return c
    try:
        with _pinned_tls_connect(ctx, host, port, make):
            return True
    except Exception:
        return False

def tls_certificate(ctx):
    """In-process TLS hygiene SUBSET (spec section 7B): certificate validity,
    negotiated protocol/cipher, and deprecated-protocol acceptance. This is
    NOT a full testssl-style enumeration; it replaces the disabled subprocess
    adapter with checks that stay inside the pinned, scope-guarded transport."""
    c, out = CHECK_BY_ID["tls-certificate"], []
    host = ctx.guard.base_host
    # For an https target use its port; for an http target probe the standard
    # https port (the http->https upgrade triple the guard already permits).
    port = ctx.guard.base_port if ctx.guard.base_scheme == "https" else 443
    try:
        with _pinned_tls_connect(ctx, host, port, ssl.create_default_context) as ssock:
            cert = ssock.getpeercert()
            proto = ssock.version()
            cipher = ssock.cipher()
        exp = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days = (exp - datetime.datetime.utcnow()).days
        cipher_s = f"{cipher[0]} ({cipher[1]}, {cipher[2]} bits)" if cipher else "unknown"
        if days < 0:
            out.append(_f(c, "high", STATUS_CONFIRMED, "high", host,
                          description="TLS certificate is expired.",
                          evidence=f"notAfter={cert['notAfter']}",
                          remediation="Renew the certificate immediately.", cwe="CWE-295"))
        elif days < 30:
            out.append(_f(c, "low", STATUS_CONFIRMED, "high", host,
                          description=f"TLS certificate expires in {days} days.",
                          evidence=f"notAfter={cert['notAfter']}",
                          remediation="Renew the certificate before expiry."))
        else:
            out.append(_f(c, "info", "not-detected", "high", host,
                          description=f"Certificate valid ({days} days left), negotiated {proto}.",
                          evidence=f"notAfter={cert['notAfter']}; protocol={proto}; cipher={cipher_s}"))
        if proto and proto in ("TLSv1", "TLSv1.1"):
            out.append(_f(c, "medium", STATUS_CONFIRMED, "high", host,
                          description=f"Deprecated protocol negotiated: {proto}.",
                          evidence=f"server selected {proto} on a modern-client handshake",
                          impact="TLS 1.0/1.1 have known cryptographic weaknesses and are deprecated by major browsers.",
                          remediation="Disable TLS 1.0/1.1; require TLS 1.2+ (prefer 1.3).",
                          cwe="CWE-327"))
        for ver, label in ((ssl.TLSVersion.TLSv1, "TLS 1.0"),
                           (ssl.TLSVersion.TLSv1_1, "TLS 1.1")):
            if proto and proto in ("TLSv1", "TLSv1.1") and label == {"TLSv1": "TLS 1.0", "TLSv1.1": "TLS 1.1"}[proto]:
                continue  # already reported via negotiated version
            if _deprecated_tls_accepted(ctx, host, port, ver):
                out.append(_f(c, "medium", STATUS_CONFIRMED, "high", host,
                              description=f"Server accepts deprecated {label} connections.",
                              evidence=f"completed a pinned handshake forced to {label}",
                              impact="Clients can be downgraded to a deprecated protocol version.",
                              remediation=f"Disable {label}; require TLS 1.2+ (prefer 1.3).",
                              cwe="CWE-327"))
    except ssl.SSLCertVerificationError as e:
        out.append(_f(c, "high", STATUS_CONFIRMED, "high", host,
                      description="TLS certificate validation failed.",
                      evidence=str(e), cwe="CWE-295",
                      remediation="Fix the certificate chain/hostname configuration."))
    except (socket.error, ssl.SSLError, ValueError) as e:
        out.append(_f(c, "info", STATUS_INCONCLUSIVE, "low", host,
                      description="TLS handshake could not be completed.",
                      evidence=f"{type(e).__name__}: {e}",
                      preconditions="TLS service reachable on the scanned port"))
    except Exception as e:
        out.append(_f(c, "info", STATUS_INCONCLUSIVE, "low", host,
                      description="TLS check could not run within the approved scope.",
                      evidence=f"{type(e).__name__}: {e}",
                      preconditions="(scheme, host, port) inside approved scope"))
    return out

SECURITY_HEADERS = [
    ("content-security-policy", "Content-Security-Policy", "medium",
     "Without a CSP, the browser lacks an explicit policy restricting script and resource origins. This is a hardening gap; it does not by itself prove injected scripts would run."),
    ("strict-transport-security", "Strict-Transport-Security", "low",
     "HSTS tells browsers to always use HTTPS for this host."),
    ("x-content-type-options", "X-Content-Type-Options", "low",
     "Without 'nosniff', some browsers may MIME-sniff responses."),
    ("referrer-policy", "Referrer-Policy", "info",
     "A referrer policy limits URL data leaked to third parties."),
    ("x-frame-options", "X-Frame-Options / frame-ancestors", "low",
     "Framing controls reduce clickjacking exposure where applicable."),
]

def security_headers(ctx):
    c, out = CHECK_BY_ID["security-headers"], []
    r = ctx.baseline()
    if r.error:
        return [_f(c, "info", STATUS_INCONCLUSIVE, "low", ctx.guard.base,
                   description="Baseline response unavailable.", evidence=r.error)]
    headers = {k.lower(): v for k, v in r.headers.items()}
    for key, name, sev, why in SECURITY_HEADERS:
        present = key in headers or (key == "x-frame-options" and
                    "frame-ancestors" in headers.get("content-security-policy", ""))
        if present:
            out.append(_f(c, "info", "not-detected", "high", r.url,
                          description=f"{name} is set.", evidence=f"{name}: {headers.get(key,'(via CSP)')}"))
        else:
            out.append(_f(c, sev, STATUS_POTENTIAL, "medium", r.url, kind="hardening",
                          description=f"{name} is not set. {why}",
                          evidence=f"Response headers on {r.url} do not include {name}.",
                          remediation=f"Set a suitable {name} header after reviewing applicability."))
    return out

def cookie_flags(ctx):
    c, out = CHECK_BY_ID["cookie-flags"], []
    r = ctx.baseline()
    if r.error:
        return [_f(c, "info", STATUS_INCONCLUSIVE, "low", ctx.guard.base,
                   description="Baseline response unavailable.", evidence=r.error)]
    raw = r.headers.get("Set-Cookie")
    if not raw:
        return [_f(c, "info", "not-detected", "high", r.url,
                   description="No cookies set by the baseline response.")]
    parts = [p.strip().lower() for p in raw.split(";")]
    name = raw.split("=", 1)[0]
    problems = []
    if "secure" not in parts and r.url.startswith("https"):
        problems.append("missing Secure")
    if "httponly" not in parts:
        problems.append("missing HttpOnly")
    if not any(p.startswith("samesite") for p in parts):
        problems.append("missing SameSite")
    if problems:
        out.append(_f(c, "low", STATUS_POTENTIAL, "medium", r.url,
                      description=f"Session cookie '{name}' flags: {', '.join(problems)}.",
                      evidence=f"Set-Cookie: {name}=... ({', '.join(problems)})",
                      impact="Cookie flag gaps can increase theft/session risk depending on how the cookie is used.",
                      remediation="Set Secure, HttpOnly and SameSite on session cookies where applicable.",
                      cwe="CWE-614"))
    else:
        out.append(_f(c, "info", "not-detected", "high", r.url,
                      description=f"Cookie '{name}' has Secure/HttpOnly/SameSite flags."))
    return out

def server_disclosure(ctx):
    c = CHECK_BY_ID["server-disclosure"]
    r = ctx.baseline()
    if r.error:
        return [_f(c, "info", STATUS_INCONCLUSIVE, "low", ctx.guard.base,
                   description="Baseline response unavailable.", evidence=r.error)]
    server = r.headers.get("Server", "")
    powered = r.headers.get("X-Powered-By", "")
    findings = []
    if re.search(r"\d", server) or re.search(r"\d", powered):
        findings.append(_f(c, "info", STATUS_CONFIRMED, "high", r.url, kind="observation",
            description="Observation (not a vulnerability by itself): server/version disclosure in response headers.",
            evidence=f"Server: {server}" + (f"; X-Powered-By: {powered}" if powered else ""),
            impact="Version details help attackers select known exploits for that software.",
            remediation="Reduce version detail in Server/X-Powered-By headers."))
    else:
        findings.append(_f(c, "info", "not-detected", "high", r.url,
                           description="No detailed version disclosure in headers."))
    return findings

def forms_review(ctx):
    c, out = CHECK_BY_ID["forms-review"], []
    r = ctx.baseline()
    if r.error:
        return [_f(c, "info", STATUS_INCONCLUSIVE, "low", ctx.guard.base,
                   description="Baseline response unavailable.", evidence=r.error)]
    forms = re.findall(r"(?is)<form\b.*?</form>", r.body)
    if not forms:
        return [_f(c, "info", "not-detected", "high", r.url, description="No forms on the landing page.")]
    for i, form in enumerate(forms):
        action = re.search(r'(?i)action=["\']?([^"\'>\s]*)', form)
        method = (re.search(r'(?i)method=["\']?(\w+)', form) or [None, "get"])[1].lower()
        has_pw = 'type="password"' in form.lower() or "type='password'" in form.lower()
        has_csrf = re.search(r"(?i)(csrf|token|nonce|authenticity)", form) is not None
        act = action.group(1) if action else "(self)"
        if has_pw and act.lower().startswith("http://"):
            out.append(_f(c, "high", STATUS_CONFIRMED, "high", r.url,
                          description=f"Password form #{i+1} submits over plain HTTP.",
                          evidence=f"action={act} method={method}",
                          impact="Credentials would be transmitted unencrypted.",
                          remediation="Submit authentication forms only to HTTPS endpoints.",
                          cwe="CWE-319"))
        elif method == "post" and not has_csrf:
            out.append(_f(c, "medium", STATUS_POTENTIAL, "low", r.url,
                          description=f"POST form #{i+1} shows no CSRF token in markup.",
                          evidence=f"action={act}; no token-like field found",
                          impact="Exploitability depends on SameSite cookies and origin checks - flagged for review, not confirmed.",
                          remediation="Verify CSRF defenses (token or SameSite+origin validation) on this endpoint.",
                          preconditions="Manual review of server-side CSRF handling"))
    if not out:
        out.append(_f(c, "info", "not-detected", "medium", r.url,
                      description=f"{len(forms)} form(s) reviewed; no obvious transport/token issue in markup."))
    return out

def mixed_content(ctx):
    c = CHECK_BY_ID["mixed-content"]
    r = ctx.baseline()
    if r.error or not r.url.startswith("https"):
        return [_f(c, "info", "not-tested", "high", ctx.guard.base,
                   description="Mixed-content check applies only to HTTPS pages with a baseline response.")]
    refs = re.findall(r'(?i)(?:src|href)=["\'](http://[^"\']+)', r.body)
    refs = [u for u in refs if "localhost" not in u]
    if refs:
        return [_f(c, "low", STATUS_CONFIRMED, "high", r.url,
                   description=f"{len(refs)} HTTP subresource reference(s) on an HTTPS page.",
                   evidence="; ".join(refs[:5]),
                   impact="Active mixed content is blocked by browsers; passive content weakens page integrity.",
                   remediation="Serve all subresources over HTTPS.", cwe="CWE-319")]
    return [_f(c, "info", "not-detected", "high", r.url,
               description="No HTTP subresource references found on the HTTPS page.")]

COMMON_EXPOSED = [
    ("/.git/HEAD", re.compile(r"ref:\s*refs/"), "high",
     "Git repository metadata appears publicly accessible.",
     "Block access to .git and never deploy VCS directories to web roots."),
    ("/.env", "NO_BODY", "high", "", ""),
    ("/server-status", re.compile(r"(?i)apache|server uptime"), "medium",
     "Server status page appears publicly accessible.",
     "Restrict server-status to localhost/ops networks."),
]

def exposed_files(ctx):
    c, out = CHECK_BY_ID["exposed-files"], []
    for path, marker, sev, desc, fix in COMMON_EXPOSED:
        r = ctx.client.get(path, read_body=(marker != "NO_BODY"))
        if r.error:
            out.append(_f(c, "info", STATUS_INCONCLUSIVE, "low", path,
                          description=f"Could not check {path}: {r.error}"))
            continue
        if marker == "NO_BODY":
            # Never read a potential secret file's body. Status + size only.
            if r.status == 200:
                out.append(_f(c, sev, STATUS_POTENTIAL, "low", r.url,
                    description=f"{path} returns HTTP 200. The response body was deliberately NOT read or stored, so exposure is unverified - a 200 here can also be a soft-404. Manual verification required.",
                    evidence=f"GET {path} -> {r.status}; connection closed after headers, body never read or stored",
                    impact="If real, environment files commonly contain credentials and secrets.",
                    remediation="Block web access to .env; verify manually; rotate any secrets if exposure is confirmed.",
                    preconditions="Owner-side verification that the 200 response actually contains environment data"))
            else:
                out.append(_f(c, "info", "not-detected", "medium", r.url,
                              description=f"{path} not exposed (HTTP {r.status})."))
        elif marker and r.status == 200 and marker.search(r.body):
            n_lines = len([l for l in r.body.splitlines() if l.strip()])
            ev = f"GET {path} -> 200, pattern matched ({n_lines} line(s))"
            if path == "/.git/HEAD":
                ev += f"; content: {r.body[:40]!r}"   # ref line only, not secret
            out.append(_f(c, sev, STATUS_CONFIRMED, "medium", r.url,
                          description=desc, evidence=ev, remediation=fix))
        elif marker:
            out.append(_f(c, "info", "not-detected", "medium", r.url,
                          description=f"{path} not exposed (HTTP {r.status})."))
    return out

def benign_discovery(ctx):
    """Informational discovery only - presence of these files is good practice,
    never a finding."""
    c = CHECK_BY_ID["benign-discovery"]
    out = []
    for path in ("/robots.txt", "/.well-known/security.txt"):
        r = ctx.client.get(path)
        if r.status == 200:
            out.append(_f(c, "info", "not-detected", "high", r.url, kind="observation",
                          description=f"Observation: {path} present (good practice, not a finding).",
                          evidence=f"HTTP 200, {len(r.body)} bytes"))
        else:
            out.append(_f(c, "info", "not-detected", "medium", r.url, kind="observation",
                          description=f"Observation: {path} not present (HTTP {r.status}); optional."))
    return out

def cors_review(ctx):
    c = CHECK_BY_ID["cors-review"]
    r = ctx.client.get("/", headers={"Origin": "https://scanner-originated.example.invalid"})
    if r.error:
        return [_f(c, "info", STATUS_INCONCLUSIVE, "low", ctx.guard.base,
                   description="CORS probe failed.", evidence=r.error)]
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
    if acao == "*" and acac == "true":
        return [_f(c, "low", STATUS_POTENTIAL, "medium", r.url,
                   description="CORS combines a wildcard origin with Access-Control-Allow-Credentials: true. Browsers refuse credentialed wildcard requests, so this combination does not by itself expose credentialed data - but it signals a misconfigured policy worth review.",
                   evidence=f"ACAO: {acao}; ACAC: {acac}",
                   impact="Configuration smell; actual exposure depends on whether any origin is reflected elsewhere.",
                   remediation="Use an explicit origin allowlist and do not send credentials flag with a wildcard.",
                   cwe="CWE-942", kind="hardening")]
    if acao == "https://scanner-originated.example.invalid" and acac == "true":
        return [_f(c, "high", STATUS_CONFIRMED, "high", r.url,
                   description="Confirmed misconfiguration: CORS reflects an arbitrary origin AND allows credentials. Whether sensitive data is actually readable cross-origin was NOT verified - that requires an approved readable sensitive endpoint or test account.",
                   evidence=f"Origin probe answered with ACAO: {acao}; ACAC: {acac}",
                   impact="If any sensitive endpoint shares this policy, any website could make credentialed cross-origin reads. Actual data exposure unverified in this scan.",
                   remediation="Use an explicit origin allowlist for sensitive endpoints.",
                   preconditions="Verification of a sensitive response readable through this policy",
                   cwe="CWE-942")]
    if acao in ("*", "https://scanner-originated.example.invalid"):
        return [_f(c, "low", STATUS_POTENTIAL, "medium", r.url,
                   description=f"CORS reflects/permits arbitrary origins without credentials (ACAO: {acao}).",
                   evidence=f"Origin probe answered with ACAO: {acao}",
                   impact="Impact depends on what data endpoints expose cross-origin.",
                   remediation="Use an explicit origin allowlist for sensitive endpoints.",
                   kind="hardening")]
    return [_f(c, "info", "not-detected", "high", r.url,
               description="CORS does not allow arbitrary origins on the baseline endpoint.")]

def redirect_chain(ctx):
    c = CHECK_BY_ID["redirect-chain"]
    r = ctx.baseline()
    hops = getattr(r, "hops", None)
    return [_f(c, "info", "not-detected", "medium", ctx.guard.base,
               description=f"Final URL after redirects: {r.url} (status {r.status}).",
               evidence=f"requests used: {ctx.client.used}")]

def tech_fingerprint(ctx):
    c = CHECK_BY_ID["tech-fingerprint"]
    r = ctx.baseline()
    if r.error:
        return [_f(c, "info", STATUS_INCONCLUSIVE, "low", ctx.guard.base,
                   description="Baseline response unavailable.", evidence=r.error)]
    found = []
    gen = re.search(r'(?i)<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', r.body)
    if gen:
        found.append(f"generator={gen.group(1)}")
    for sig, name in [(r"wp-content", "WordPress"), (r"Drupal\.settings", "Drupal"),
                      (r"/__next/", "Next.js"), (r"ng-app", "AngularJS")]:
        if re.search(sig, r.body):
            found.append(name)
    if found:
        return [_f(c, "info", STATUS_CONFIRMED, "medium", r.url, kind="observation",
                   description="Observation (not a vulnerability by itself). Technology fingerprint: " + ", ".join(found),
                   evidence="observed in public HTML",
                   impact="Fingerprinting is informational; a version match alone does not prove exploitability.")]
    return [_f(c, "info", "not-detected", "medium", r.url,
               description="No obvious technology fingerprint in public HTML.")]

CHECKS = [
    Check("https-enforcement", "HTTPS enforcement", "transport", https_enforcement),
    Check("tls-certificate", "TLS certificate and protocol (in-process subset)", "transport", tls_certificate),
    Check("security-headers", "HTTP security headers", "http-browser", security_headers),
    Check("cookie-flags", "Cookie security flags", "http-browser", cookie_flags),
    Check("server-disclosure", "Server information disclosure", "http-browser", server_disclosure),
    Check("forms-review", "Form transport and CSRF review", "webapp", forms_review),
    Check("mixed-content", "Mixed content", "transport", mixed_content),
    Check("benign-discovery", "Benign file discovery (robots/security.txt)", "attack-surface", benign_discovery),
    Check("cors-review", "CORS configuration", "http-browser", cors_review),
    Check("tech-fingerprint", "Technology fingerprint", "attack-surface", tech_fingerprint),
    # Active path probes - NOT passive; profile 2 only, after ownership verification:
    Check("exposed-files", "Active probe: sensitive file paths", "attack-surface", exposed_files,
          profiles=(2,)),
]
CHECK_BY_ID = {c.id: c for c in CHECKS}
