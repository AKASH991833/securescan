# Roadmap (priority order)

DONE: AI provider abstraction (keyless; activates on SECURESCAN_AI_KEY).
DONE: Crawler + profile 2 subset (same-origin GET-only crawl, per-page checks).
DONE: First real scanner adapter (testssl.sh, user-space free install).
DONE: Background job queue + cancellation (in-process JobManager).
DONE: Auth + tenant isolation (argon2, org scoping, cross-tenant 404s) - local.
DONE: DNS TXT verification via dnspython (no dig dependency).
DONE: Retest/compare across scans.
DONE: Retest comparison UI on scan page; job progress/cancel UI.
DONE: Shared-deploy mode (SECURESCAN_DEPLOY=shared): stable secret required,
Secure cookies. Still not publicly deployed.
1. Rate limiting on scan creation itself (abuse control) for shared deploys.
2. More adapters ONLY if they can run pinned (subprocess DNS rule).
3. GitHub publication - grant evidence recovered (Oct 7 verbatim exchange);
   main to confirm scope for THIS project + sanitization review.
4. Hosted deployment: research done - see DEPLOYMENT_NOTES.md.
5. Multi-worker deployment (Redis/Celery) only when real deployment decided.
