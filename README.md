# SecureScan (local prototype)

Authorized-use website security assessment platform. Profile 1 (external
passive audit) and a profile-2 subset (same-origin crawl + labeled active
path probes) are implemented; profiles 3-5 stay registered as unavailable
with honest reasons. Multi-tenant auth, ownership verification, background
jobs with cancellation, retest comparison, JSON/PDF reports. 64 tests. Only scan systems you own or are explicitly authorized to test.

## Run (Windows, near-one-click)
    Double-click setup-securescan.bat once, then start-securescan.bat.
    Details + honest limits: docs/WINDOWS.md

## Run (Linux/macOS)
    pip install --user -r requirements.txt
    python3 -m securescan.webapp      # UI on http://127.0.0.1:5001
    python3 run_scan.py <target> --profile 1 --json-out out.json --pdf-out out.pdf

## Test (local intentionally-misconfigured fixtures only)
    python3 -m pytest tests/ -q       # 64 tests

The CLI flag --allow-private-fixture is for the local test harness ONLY.
The web UI cannot scan private/localhost addresses.

## Setup
    pip install --user -r requirements.txt
    python3 -m pytest tests/ -q          # 64 tests
    python3 -m securescan.webapp         # local only: http://127.0.0.1:5001

## Environment
    SECURESCAN_SECRET     session signing key (required for shared deploys)
    SECURESCAN_DEPLOY     "local" (default) or "shared" (requires SECRET, Secure cookies, TLS)
    SECURESCAN_AI_KEY     user's own project Gemini key -> enables ExternalProvider
                          (or stored locally via `python -m securescan.local_key setup`:
                          masked input, DPAPI-encrypted on Windows, outside the repo)
    SECURESCAN_DEMO=1     local-only seeded demo tenant (never in shared deploys)

## Known limits
Local prototype: SQLite storage, in-process queue (durable records, jobs from a
dead process marked interrupted), profiles 3-5 unavailable, active scanner
integrations unavailable (subprocess pinning rule); TLS hygiene (certificate,
negotiated protocol/cipher, deprecated-protocol acceptance) is checked
in-process over the pinned transport instead - a subset, not testssl parity.
AI explainer verified with a
project-dedicated Gemini key (free tier, stored outside the repo); without a
key it falls back to a labeled local template (NOT AI).
