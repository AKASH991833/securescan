# Roadmap (priority order)

DONE: AI provider abstraction (keyless; activates on SECURESCAN_AI_KEY).
DONE: Crawler + profile 2 subset (same-origin GET-only crawl, per-page checks).
DONE: First real scanner adapter (testssl.sh, user-space free install).
DONE: Background job queue + cancellation (in-process JobManager).
DONE: Auth + tenant isolation (argon2, org scoping, cross-tenant 404s) - local.
DONE: DNS TXT verification via dnspython (no dig dependency).
DONE: Retest/compare across scans.
1. Retest UI surface (compare endpoint/page; function + test exist).
2. Persistent session secret management for any shared deployment.
3. More adapters ONLY if they can run pinned (subprocess DNS rule).
4. GitHub publication - requires explicit grant for THIS project +
   sanitization review before pushing.
5. Multi-worker deployment (Redis/Celery) only when real deployment decided.
