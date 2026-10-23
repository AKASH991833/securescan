# SecureScan (local prototype)

Authorized-use website security assessment platform. Profile 1 (external
passive audit) implemented; profiles 2-5 registered as unavailable with honest
reasons. Only scan systems you own or are explicitly authorized to test.

## Run
    pip install flask pytest          # user site
    python3 -m securescan.webapp      # UI on http://127.0.0.1:5001
    python3 run_scan.py <target> --profile 1 --json-out out.json --pdf-out out.pdf

## Test (local intentionally-misconfigured fixtures only)
    python3 -m pytest tests/ -q       # 16 tests

The CLI flag --allow-private-fixture is for the local test harness ONLY.
The web UI cannot scan private/localhost addresses.

## Setup
    pip install --user -r requirements.txt
    python3 -m pytest tests/ -q          # 55 tests
    python3 -m securescan.webapp         # local only: http://127.0.0.1:5001

## Environment
    SECURESCAN_SECRET     session signing key (required for shared deploys)
    SECURESCAN_DEPLOY     "local" (default) or "shared" (requires SECRET, Secure cookies, TLS)
    SECURESCAN_AI_KEY     user's own project Gemini key -> enables ExternalProvider
    SECURESCAN_DEMO=1     local-only seeded demo tenant (never in shared deploys)

## Known limits
Local prototype: SQLite storage, in-process queue (durable records, jobs from a
dead process marked interrupted), profiles 3-5 unavailable, active scanner
integrations unavailable (subprocess pinning rule), AI needs user's own key.
