"""External tool adapters. Runtime-detected; missing tools are reported, never
faked. First real adapter: testssl.sh (TLS deep check, profile 2+)."""
import json, shutil, subprocess, tempfile
from .findings import Finding, STATUS_CONFIRMED, STATUS_INCONCLUSIVE

def testssl_available():
    return shutil.which("testssl.sh")

def run_testssl(host: str, port: int, timeout: int = 60, tls_expected: bool = True):
    """Returns (findings, coverage_detail). Honest on any failure."""
    if not tls_expected:
        return [], "testssl.sh skipped: target is plain HTTP (no TLS service expected)"
    if not testssl_available():
        return [], "testssl.sh not installed - TLS deep check not run"
    out_file = tempfile.mktemp(suffix=".json")
    try:
        proc = subprocess.run(
            ["testssl.sh", "--quiet", "--jsonfile", out_file, f"{host}:{port}"],
            capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return [], "testssl.sh timed out - TLS deep check inconclusive"
    try:
        data = json.load(open(out_file))
    except (OSError, json.JSONDecodeError):
        return [], "testssl.sh produced no parseable output - TLS deep check inconclusive"
    findings = []
    asset = f"{host}:{port}"
    for item in data:
        iid, sev = item.get("id", ""), (item.get("severity") or "").upper()
        finding_txt = item.get("finding", "")
        if iid == "cert_expiration_status" and sev in ("HIGH", "CRITICAL"):
            findings.append(Finding(check_id="testssl", title="TLS certificate expiry (testssl.sh)",
                category="transport", severity="high", status=STATUS_CONFIRMED,
                confidence="high", asset=asset, description=str(finding_txt),
                remediation="Renew the certificate.", cwe="CWE-295"))
        elif iid in ("SSLv2", "SSLv3") and sev in ("HIGH", "CRITICAL"):
            findings.append(Finding(check_id="testssl", title=f"Obsolete protocol offered: {iid}",
                category="transport", severity="high", status=STATUS_CONFIRMED,
                confidence="high", asset=asset, description=str(finding_txt),
                remediation=f"Disable {iid}.", cwe="CWE-327"))
    detail = f"testssl.sh completed, {len(data)} raw item(s), {len(findings)} finding(s)"
    if not findings:
        detail += " (no critical/high items, or no TLS service on this port)"
    return findings, detail
