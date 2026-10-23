# Deployment notes (free / no-card constraint, researched 2026-10-23)

## Verified options

- **Render free web services** (render.com/docs/free): free tier exists, no
  card required; services spin down after 15 min without traffic (~1 min cold
  start, render.com/docs/faq); filesystem is ephemeral, so the SQLite findings
  DB resets on redeploy/restart unless a paid disk is attached. Outbound
  network access is unrestricted, which a scanner needs. Docs explicitly say
  free instances are not for production.
- **PythonAnywhere free**: NOT viable for this product - free accounts route
  outbound traffic through a proxy allowlist of approved sites
  (help.pythonanywhere.com/pages/403ForbiddenError,
  pythonanywhere.com/whitelist). A security scanner must reach arbitrary
  user-owned domains, which the allowlist blocks by design.

## AI analysis path (project-authorized)

- The ExternalProvider activates on SECURESCAN_AI_KEY. DONE Oct 23 2026:
  a project-dedicated Gemini API key (free tier) was created and is held
  outside this repo (never committed or logged). The provider model is
  gemini-3.1-flash-lite (heavier models timed out on the free tier; retired
  models were replaced). One real redacted-finding call verified end-to-end.
  The key never enters the repo or logs.
- Scanned content is untrusted input; before any external AI call, evidence
  is redacted (already enforced in findings) and instructions in scanned
  content are never obeyed (spec section 12).

## Honest bottom line

A free hosted deployment is possible via Render free tier with real
limitations (cold starts, ephemeral DB, not-for-production terms). The safe
local prototype remains the primary verified artifact until Akash chooses.

## Persistent free DB research (2026-10-23) - CANDIDATE, NOT SOLVED

- **Turso** (turso.tech/pricing): free tier, "no credit card required", and
  markets SQLite compatibility. STATUS: researched candidate only. No adapter
  code exists, no migration or integration test has been run, and marketing
  compatibility does not establish drop-in Python sqlite3 compatibility or
  behavior under Render's ephemeral disk. Treating durability as unsolved
  until a tested adapter exists.
- **Supabase free**: Postgres, pauses projects after 7 days of low activity
  (supabase.com/docs/guides/platform/free-project-pausing); would require
  porting the storage layer off SQLite.
- Job queue: durable job records survive LOCAL restarts (interrupted-
  marking). On Render they survive only if the DB is durable, which depends
  on the unverified Turso path above.
- Provider policy (render.com/docs/penetration-testing): Render permits
  testing of the customer's OWN services; testing other Render users' infra
  needs consent; DoS testing forbidden. A multi-tenant scanner probing
  arbitrary external hosts from Render IPs is NOT explicitly covered - it is
  a gray area needing Render confirmation before any hosted demo.
