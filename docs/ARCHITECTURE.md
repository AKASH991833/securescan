# Architecture

securescan/
  findings.py      finding schema, statuses, severity, redaction
  scope.py         normalization, ScopeGuard (SSRF defenses)
  client.py        SafeClient: budget/timeout/size caps, redirect revalidation
  checks/builtin.py 10 passive checks + registry
  profiles.py      profile definitions + runtime tool detection
  ownership.py     challenge store, web + DNS TXT verification
  orchestrator.py  stages, coverage matrix, scan runner
  store.py         SQLite persistence (scans, findings, coverage)
  explain.py       deterministic template explainer (NOT AI)
  report.py        JSON + PDF reports
  fixtures.py      local vuln/hardened fixture apps (127.0.0.1 only)
  webapp.py        Flask dark-console UI with ownership gate
run_scan.py        CLI
tests/             pytest suite (16 tests)

Data flow: target -> normalize -> scope guard -> safe client -> checks ->
findings (redacted) -> SQLite -> JSON/PDF + UI. Every hop revalidated.
