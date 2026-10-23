# Security Model

- Authorization first: the web UI rejects prohibited targets (private/metadata)
  BEFORE issuing any challenge or making any network fetch. It will not scan a
  host until ownership is proven via a random, expiring, single-use web
  challenge fetched through the same pinned, scope-guarded transport (DNS TXT
  supported when a resolver tool exists). Verification grants a 1-hour window.
- Scope enforcement: every request and every redirect hop is revalidated
  (scheme, host allowlist, fresh DNS resolution + IP screening). The socket
  connection is then PINNED to the exact validated IPs (patched resolver for
  the connect only) while Host header, TLS SNI and certificate verification
  keep the real hostname - a DNS change between validation and connect
  (rebinding) cannot redirect traffic. Localhost, private, link-local,
  reserved, multicast and cloud-metadata IPs are rejected; metadata IPs are
  rejected even in the test-harness private mode.
- Test-only private allowance: `allow_private` exists only on the
  orchestrator/CLI for the local fixture harness. The web UI never sets it;
  there is no user-controlled bypass.
- No destructive testing: no exploitation, extraction, password attacks,
  shells, or DoS - by design, not just configuration.
- Evidence hygiene: secrets, tokens, cookies, authorization headers are
  redacted before storage/display.
- Honest statuses and kinds: findings carry kind = vulnerability | hardening |
  observation. Missing headers are potential hardening gaps; version disclosure
  and fingerprints are confirmed OBSERVATIONS, not vulnerabilities; CORS
  wildcard+credentials is a hardening review item (browsers refuse it), while a
  REFLECTED origin with credentials is confirmed. robots.txt/security.txt are
  benign discovery, never findings.
- Untrusted content: scanned HTML is data; nothing in it is executed or obeyed.
