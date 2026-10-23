"""Per-page checks for profile 2 (run across crawled pages)."""
import re
from ..findings import Finding, STATUS_POTENTIAL, STATUS_CONFIRMED

def page_findings(pages):
    out = []
    for r in pages:
        forms = re.findall(r"(?is)<form\b.*?</form>", r.body)
        for i, form in enumerate(forms):
            method = (re.search(r'(?i)method=["\']?(\w+)', form) or [None, "get"])[1].lower()
            has_csrf = re.search(r"(?i)(csrf|token|nonce|authenticity)", form) is not None
            action = re.search(r'(?i)action=["\']?([^"\'>\s]*)', form)
            act = action.group(1) if action else "(self)"
            if has_pw(form) and act.lower().startswith("http://"):
                out.append(Finding(check_id="page-forms", title="Password form over HTTP (crawl)",
                    category="webapp", severity="high", status=STATUS_CONFIRMED,
                    confidence="high", asset=r.url,
                    description=f"Password form #{i+1} on crawled page submits over plain HTTP.",
                    evidence=f"action={act}", cwe="CWE-319",
                    remediation="Submit authentication forms only to HTTPS endpoints."))
            elif method == "post" and not has_csrf:
                out.append(Finding(check_id="page-forms", title="POST form without CSRF token (crawl)",
                    category="webapp", severity="medium", status=STATUS_POTENTIAL,
                    confidence="low", asset=r.url,
                    description=f"POST form #{i+1} on crawled page shows no CSRF token in markup.",
                    evidence=f"action={act}; no token-like field found",
                    impact="Exploitability depends on SameSite cookies and origin checks - flagged for review, not confirmed.",
                    remediation="Verify CSRF defenses on this endpoint.",
                    preconditions="Manual review of server-side CSRF handling"))
        if r.url.startswith("https"):
            refs = [u for u in re.findall(r'(?i)(?:src|href)=["\'](http://[^"\']+)', r.body)]
            if refs:
                out.append(Finding(check_id="page-mixed-content", title="Mixed content (crawl)",
                    category="transport", severity="low", status=STATUS_CONFIRMED,
                    confidence="high", asset=r.url,
                    description=f"{len(refs)} HTTP subresource reference(s) on HTTPS page.",
                    evidence="; ".join(refs[:5]), cwe="CWE-319",
                    remediation="Serve all subresources over HTTPS."))
    return out

def has_pw(form_html):
    f = form_html.lower()
    return 'type="password"' in f or "type='password'" in f
