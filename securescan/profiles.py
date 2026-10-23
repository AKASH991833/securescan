"""Scan profiles (spec section 8). Only what is actually implemented is
marked available; the rest is registered as unavailable with reasons."""
from .checks import REGISTRY

PROFILES = {
    1: {
        "name": "External Passive Audit",
        "available": True,
        "checks": [cid for cid, c in REGISTRY.items() if 1 in c.profiles],
        "description": "Passive only: public HTTP responses, TLS, headers, cookies, forms markup review, benign discovery. No path probing, no aggressive testing.",
    },
    2: {
        "name": "Standard External Security Audit",
        "available": True,
        "partial": True,
        "checks": list(REGISTRY),
        "description": "Passive checks PLUS same-origin GET-only crawl (max 10 pages), per-page form/mixed-content review, and ACTIVE PATH PROBES for well-known sensitive files (.git/HEAD, .env, server-status). SUBSET ONLY: Nuclei/ZAP active vulnerability tests and API scanning are absent (binaries not installed) - every report lists this gap.",
    },
    3: {
        "name": "Advanced Authorized Assessment",
        "available": False,
        "checks": [],
        "description": "Would add explicitly approved active tests.",
        "unavailable_reason": "Requires scanner integrations and explicit scope approval workflow; not built.",
    },
    4: {
        "name": "Authenticated Assessment",
        "available": False,
        "checks": [],
        "description": "Would use dedicated test accounts for login-dependent tests.",
        "unavailable_reason": "Test-account workflow not built.",
    },
    5: {
        "name": "Source and Dependency Audit",
        "available": False,
        "checks": [],
        "description": "Would run SAST/secret/dependency scans on user-supplied source.",
        "unavailable_reason": "Semgrep/Gitleaks/Trivy not installed in this environment.",
    },
}

def external_tools_status():
    """Detect scanner binaries honestly at runtime (spec section 6)."""
    import shutil
    tools = ["zap", "nuclei", "nikto", "nmap", "wpscan", "trivy", "syft",
             "grype", "semgrep", "gitleaks", "testssl.sh", "playwright"]
    return {t: (shutil.which(t) or None) for t in tools}
