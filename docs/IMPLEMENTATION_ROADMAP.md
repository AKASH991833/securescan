# Roadmap (priority order)

DONE: AI provider abstraction - REAL AI VERIFIED Oct 23 2026: project-dedicated Gemini key (free tier, held outside the repo), one real redacted-finding call through gemini-3.1-flash-lite; template fallback when SECURESCAN_AI_KEY unset.
DONE: Crawler + profile 2 subset (same-origin GET-only crawl, per-page checks).
DONE: In-process TLS hygiene subset over the pinned transport (no subprocess, no DNS rebypass; replaces the disabled testssl adapter for the certificate/protocol scope).
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
