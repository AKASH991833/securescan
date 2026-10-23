"""JSON + PDF reports with accurate coverage (spec section 13).
Never describes an unexecuted test as completed."""
from __future__ import annotations
import json, time
from .ai_provider import get_provider, ai_status

def build_json(result: dict) -> dict:
    scan, findings, cov = result["scan"], result["findings"], result["coverage"]
    return {
        "tool": "SecureScan 0.1 (local prototype)",
        "generated_at": time.time(),
        "target": scan["target"], "profile": scan["profile"],
        "status": scan["status"], "error": scan["error"],
        "summary": {
            "total_records": len(findings),
            "vulnerabilities_confirmed": sum(1 for f in findings if f["status"] == "confirmed" and f.get("kind", "vulnerability") == "vulnerability"),
            "confirmed": sum(1 for f in findings if f["status"] == "confirmed"),
            "potential": sum(1 for f in findings if f["status"] == "potential"),
            "inconclusive": sum(1 for f in findings if f["status"] == "inconclusive"),
            "not_detected": sum(1 for f in findings if f["status"] == "not-detected"),
            "observations": sum(1 for f in findings if f.get("kind") == "observation"),
            "hardening": sum(1 for f in findings if f.get("kind") == "hardening"),
        },
        "ai_status": ai_status(),
        "findings": [{**f, "explanation": get_provider().explain(f)} for f in findings],
        "coverage": cov,
        "disclaimer": ("Automated passive audit. Absence of a finding is not proof of "
                       "absence of vulnerability; see coverage list for tests not run."),
    }

def build_pdf(result: dict, path: str):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.pdfgen import canvas
    data = build_json(result)
    c = canvas.Canvas(path, pagesize=A4)
    w, h = A4
    y = h - 20*mm
    def line(txt, size=9, dy=5.2):
        nonlocal y
        if y < 20*mm:
            c.showPage(); y = h - 20*mm
        c.setFont("Helvetica", size)
        c.drawString(15*mm, y, txt[:120])
        y -= dy*mm
    c.setFont("Helvetica-Bold", 16); c.drawString(15*mm, y, "SecureScan Security Report"); y -= 10*mm
    line(f"Target: {data['target']}   Profile: {data['profile']}   Status: {data['status']}", 10)
    s = data["summary"]
    line(f"Confirmed: {s['confirmed']}  Potential: {s['potential']}  "
         f"Inconclusive: {s['inconclusive']}  Not detected: {s['not_detected']}", 10)
    y -= 4*mm
    line("FINDINGS", 12, 7)
    for f in data["findings"]:
        line(f"[{f['severity'].upper()} / {f['status']}] {f['title']}", 10, 6)
        line(f"  Asset: {f['asset']}", 8)
        if f["description"]:
            line("  " + f["description"], 8)
        if f["evidence"]:
            line("  Evidence: " + f["evidence"][:100], 8)
        if f["remediation"]:
            line("  Fix: " + f["remediation"][:110], 8)
        y -= 2*mm
    y -= 4*mm
    line("COVERAGE (tests not run are listed, never implied)", 12, 7)
    for row in data["coverage"]:
        line(f"  {row['state']:12s} {row['check_id']} - {row['detail'][:80]}", 8)
    y -= 4*mm
    line(data["disclaimer"], 8)
    c.save()
    return path


def _fkey(f):
    return (f["check_id"], f["title"], f["asset"])

def compare_scans(old: dict, new: dict) -> dict:
    """Retest report (spec section 13): fixed / still-open / new.
    Reopened requires history beyond two scans; reported when detectable."""
    old_keys = {_fkey(f): f for f in old["findings"]
                if f["status"] in ("confirmed", "potential")}
    new_keys = {_fkey(f): f for f in new["findings"]
                if f["status"] in ("confirmed", "potential")}
    fixed = [k for k in old_keys if k not in new_keys]
    still_open = [k for k in old_keys if k in new_keys]
    new_found = [k for k in new_keys if k not in old_keys]
    return {"fixed": [f"{t} ({a})" for _, t, a in fixed],
            "still_open": [f"{t} ({a})" for _, t, a in still_open],
            "new": [f"{t} ({a})" for _, t, a in new_found],
            "old_scan": old["scan"]["id"], "new_scan": new["scan"]["id"]}
