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
