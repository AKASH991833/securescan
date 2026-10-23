# Scan Coverage

## Profile 1 - External Passive Audit (implemented, PASSIVE ONLY)
HTTPS enforcement, TLS certificate/protocol, security headers (CSP, HSTS,
X-Content-Type-Options, Referrer-Policy, X-Frame-Options/frame-ancestors),
cookie flags, server disclosure (recorded as observation, not vulnerability),
form transport + CSRF markup review, mixed content, CORS review, technology
fingerprint (observation), benign discovery (robots.txt / security.txt -
informational, never a finding).

## Profile 2 - Standard External Security Audit (implemented SUBSET)
Everything in profile 1, PLUS: same-origin GET-only crawl (max 10 pages),
per-page form/mixed-content review, ACTIVE PATH PROBES for well-known
sensitive files (.git/HEAD, .env, server-status - these are active requests,
not passive), TLS deep check via testssl.sh is DISABLED: the subprocess does its own DNS/networking
outside the pinned transport, so it stays unavailable rather than bypass SSRF defenses. .env contents are never retrieved or stored - only
the assignment-line pattern match is recorded.
ABSENT from profile 2 and always listed in coverage: Nuclei/ZAP active
vulnerability tests (binaries not installed), API security testing.

## Not covered (listed in every report, never implied)
- Crawling and controlled non-destructive vulnerability tests (profile 2):
  needs crawler + Nuclei/ZAP - binaries absent.
- Active authorized tests (profile 3): not built.
- Authenticated testing with test accounts (profile 4): not built.
- Source/dependency audit (profile 5): Semgrep/Gitleaks/Trivy absent.
- AI-generated analysis: no provider key; template explainer is a placeholder,
  clearly labeled not-AI.
- Port scanning, subdomain enumeration, API schema testing: not built.

## Known limits
- Version/fingerprint matches do not prove exploitability.
- Absence of a finding is not proof of absence of vulnerability.
- TLS: basic check uses the platform trust store. Deep cipher/protocol enumeration via testssl.sh is installed but DISABLED (subprocess networking would bypass the pinned transport); coverage lists it as not-tested.
