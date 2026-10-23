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

- The ExternalProvider activates on SECURESCAN_AI_KEY. The legitimate free
  path: Akash creates a Gemini API key in his own Google AI Studio FOR THIS
  PROJECT (free tier exists per ai.google.dev/gemini-api/docs/billing) and
  sets it as SECURESCAN_AI_KEY. Reusing keys created for other past projects
  is not assumed; a fresh project-scoped key keeps audit clean.
- Scanned content is untrusted input; before any external AI call, evidence
  is redacted (already enforced in findings) and instructions in scanned
  content are never obeyed (spec section 12).

## Honest bottom line

A free hosted deployment is possible via Render free tier with real
limitations (cold starts, ephemeral DB, not-for-production terms). The safe
local prototype remains the primary verified artifact until Akash chooses.

## Persistent free DB research (2026-10-23)

- **Turso** (turso.tech/pricing): free tier, "no credit card required", and it
  IS SQLite-compatible - matches the current storage layer with the least
  migration. This makes a Render-free-web-service + Turso combination the
  only verified no-card hosted path found so far: durable DB survives
  Render's ephemeral disk, unrestricted egress for scanning stays on Render.
  Real limits remain: cold starts, Render's not-for-production terms, Turso
  free quotas. NOT provisioned - deploying the unfinished scanner publicly is
  deliberately out of scope.
- **Supabase free**: Postgres, pauses projects after 7 days of low activity
  (supabase.com/docs/guides/platform/free-project-pausing); would require
  porting the storage layer off SQLite.
- Job queue on a hosted deploy: durable job records already survive restarts
  (interrupted-marking), so Render restarts lose only in-flight progress, not
  history. A multi-worker Redis/Celery setup stays a later decision.
