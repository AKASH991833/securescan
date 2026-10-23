# Project Audit (2026-10-23)

## What existed before this session
No code existed. Prior work was a private concept File (research + design +
mock console) only. No scanner, backend, database or implementation matrix had
ever been built. This repository is therefore a from-scratch implementation
that preserves the concept's visual direction (dark console, English UI).

## Environment
- Python 3.10, Flask 3.1 (user-site), SQLite 3.37, requests, reportlab, pytest 9.
- Scanner binaries absent except testssl.sh (user-space, free) - which is
  installed but deliberately DISABLED because subprocess networking would
  bypass the pinned transport. All others absent, detected, reported, never faked.
- No external AI key available (free tiers need user signup).

## Implementation matrix
| Module | State | Notes |
|---|---|---|
| Finding schema + statuses + redaction | COMPLETE | confirmed/potential/not-detected/not-tested/inconclusive; secrets redacted |
| Scope guard + SSRF protection | COMPLETE | scheme allowlist, host scope, per-hop DNS re-resolution, private/loopback/link-local/reserved/metadata rejection |
| Safe HTTP client | COMPLETE | request budget, size cap, timeout, redirect revalidation |
| 9 passive checks + benign discovery | COMPLETE | headers, cookies, TLS, HTTPS enforcement, forms, mixed content, exposed files, CORS, fingerprint, server disclosure |
| Ownership verification | COMPLETE (web challenge) | random expiring single-use tokens, replay protection; DNS TXT implemented but needs `dig` (absent) |
| Scan profiles | PARTIAL | P1 passive-only COMPLETE; P2 partial subset COMPLETE (crawl + active path probes + testssl adapter); 3-5 unavailable with reasons |
| Orchestrator + coverage matrix | COMPLETE | per-check completed/failed/not-tested recorded |
| Storage (SQLite) | COMPLETE | scans, findings, coverage |
| Reports (JSON + PDF) | COMPLETE | coverage always included; disclaimer |
| Explainer | COMPLETE (not AI) | deterministic templates, labeled not-AI |
| Web UI (dark console) | COMPLETE (local prototype) | ownership gate enforced before scan |
| CLI | COMPLETE | |
| Test suite | COMPLETE | 31 tests, all passing |
| Auth/multi-user/tenancy | MISSING | needs real deployment decisions |
| Background queue + cancellation | COMPLETE (in-process) | thread-based JobManager, cancel events honored between checks; Redis/Celery only needed for multi-worker deployment |
| Scanner integrations | BLOCKED (by design) | testssl.sh installed but DISABLED: subprocess does its own DNS/networking outside the pinned transport; stays unavailable until pinnable. No subprocess may bypass SSRF defenses |
| AI provider abstraction | COMPLETE (keyless) | provider interface + template provider active; external provider activates on SECURESCAN_AI_KEY; actual AI still unavailable without user's key |
| GitHub publication | NOT DONE | requires explicit user grant + sanitization review |
