"""Deterministic remediation explainer.

This is NOT an AI integration. It is a template-based local explainer so the
report pipeline works end to end without an external model. A real AI provider
abstraction (e.g. a user-configured Gemini free-tier key) is a documented
follow-up; until then, every explanation is labeled as template-generated.
"""
SOURCES = {
    "https-enforcement": "https://owasp.org/www-project-web-security-testing-guide/",
    "tls-certificate": "https://ssl-config.mozilla.org/",
    "security-headers": "https://owasp.org/www-project-secure-headers/",
    "cookie-flags": "https://owasp.org/www-community/controls/SecureCookieAttribute",
    "mixed-content": "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",
    "cors-review": "https://portswigger.net/web-security/cors",
    "forms-review": "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
    "exposed-files": "https://owasp.org/www-project-web-security-testing-guide/",
    "server-disclosure": "https://owasp.org/www-project-web-security-testing-guide/",
}

def explain(finding: dict) -> str:
    """Template-generated explanation. Not AI output."""
    sev = finding["severity"]
    lines = [
        f"[template-generated explanation - not AI output]",
        f"Priority: {sev}. Status: {finding['status']} (confidence: {finding['confidence']}).",
    ]
    if finding.get("impact"):
        lines.append("Why it matters: " + finding["impact"])
    if finding.get("remediation"):
        lines.append("Suggested fix: " + finding["remediation"])
    if finding.get("preconditions"):
        lines.append("Before treating as confirmed: " + finding["preconditions"])
    ref = SOURCES.get(finding["check_id"])
    if ref:
        lines.append("Reference: " + ref)
    return "\n".join(lines)
