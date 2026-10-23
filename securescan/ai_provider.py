"""AI provider abstraction (spec section 12). Exists keyless: the active
provider is selected at runtime and reports its real availability.

- TemplateProvider: deterministic local templates. NOT AI. Always available.
- ExternalProvider: stub for a user-configured hosted model (e.g. Gemini free
  tier). Unavailable until the user supplies their own key via env var
  SECURESCAN_AI_KEY. Never sends data anywhere without a configured key;
  scanned content would be redacted before any external call.
"""
import os

class TemplateProvider:
    name = "template-explainer"
    is_ai = False
    available = True
    def explain(self, finding: dict) -> str:
        from .explain import explain
        return explain(finding)

class ExternalProvider:
    name = "external-ai"
    is_ai = True
    def __init__(self):
        self.available = bool(os.environ.get("SECURESCAN_AI_KEY"))
        self.unavailable_reason = ("No user-supplied key (SECURESCAN_AI_KEY unset). "
                                   "Free-tier signup (e.g. Gemini) is the documented follow-up.")
    def explain(self, finding: dict):
        raise RuntimeError("external AI provider unavailable: " + self.unavailable_reason)

def get_provider():
    ext = ExternalProvider()
    if ext.available:
        return ext
    return TemplateProvider()

def ai_status() -> dict:
    p = get_provider()
    return {"active": p.name, "is_ai": p.is_ai, "available": p.available,
            "note": ("Template explainer active - NOT AI output." if not p.is_ai
                     else "External AI provider active.")}
