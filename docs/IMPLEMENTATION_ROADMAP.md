# Roadmap (priority order)

DONE: AI provider abstraction (keyless; activates on SECURESCAN_AI_KEY).
DONE: Crawler + profile 2 subset (same-origin GET-only crawl, per-page checks).
DONE: First real scanner adapter (testssl.sh, user-space free install).
1. Background job queue + cancellation (scans still synchronous).
2. Auth + multi-user tenancy (only when real deployment is decided).
3. DNS TXT verification tooling (needs `dig` or a DNS library).
4. Retest/compare across scans (data model already stores first/last seen).
5. More adapters if free user-space installs prove out (gitleaks, semgrep).
6. GitHub publication - standing inferred default exists (see audit); confirm
   scope for THIS project + sanitization review before pushing.
