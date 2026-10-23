#!/usr/bin/env python3
"""CLI: python3 run_scan.py <target> [--profile 1] [--json out.json] [--pdf out.pdf]
--allow-private-fixture is for the local test harness ONLY (127.0.0.1 fixtures)."""
import argparse, json, sys
from securescan.store import Store
from securescan.orchestrator import run_scan
from securescan.report import build_json, build_pdf

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--profile", type=int, default=1)
    ap.add_argument("--db", default="securescan.db")
    ap.add_argument("--json-out")
    ap.add_argument("--pdf-out")
    ap.add_argument("--allow-private-fixture", action="store_true",
                    help="TEST HARNESS ONLY: permit localhost/private targets")
    a = ap.parse_args()
    store = Store(a.db)
    result = run_scan(a.target, a.profile, store,
                      allow_private=a.allow_private_fixture)
    data = build_json(result)
    print(f"scan {data['status']}: {data['summary']}")
    for f in data["findings"]:
        if f["status"] in ("confirmed", "potential"):
            print(f"  [{f['severity']}/{f['status']}] {f['title']}: {f['description'][:100]}")
    if a.json_out:
        json.dump(data, open(a.json_out, "w"), indent=2)
        print("wrote", a.json_out)
    if a.pdf_out:
        build_pdf(result, a.pdf_out)
        print("wrote", a.pdf_out)
    return 0 if data["status"] == "complete" else 1

if __name__ == "__main__":
    sys.exit(main())
