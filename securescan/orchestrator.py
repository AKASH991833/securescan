"""Scan orchestration: stages, coverage matrix, honest per-check outcomes."""
from __future__ import annotations
import traceback
from .scope import ScopeGuard, ScopeError
from .client import SafeClient
from .checks import REGISTRY
from .checks.pages import page_findings
from .crawler import crawl
from .profiles import PROFILES
from .store import Store

STAGES = ["ownership-verification", "scope-validation", "baseline-fetch",
          "passive-checks", "evidence-normalization", "risk-analysis",
          "report-generation"]

class ScanContext:
    def __init__(self, guard, client):
        self.guard, self.client = guard, client
        self._baseline = None
    def baseline(self):
        if self._baseline is None:
            self._baseline = self.client.get("/")
        return self._baseline

def run_scan(target: str, profile: int, store: Store,
             allow_private: bool = False, budget: int = 60,
             cancel_event=None) -> dict:
    """Run a scan. `allow_private` is only for the local test fixture harness;
    the web UI and CLI never set it for user-entered targets."""
    prof = PROFILES.get(profile)
    if not prof or not prof["available"]:
        raise ValueError(f"profile {profile} is not available: "
                         f"{prof['unavailable_reason'] if prof else 'unknown'}")
    sid = store.create_scan(target, profile)
    coverage, findings = [], []
    try:
        guard = ScopeGuard(target, allow_private=allow_private)
        client = SafeClient(guard, budget=budget)
        ctx = ScanContext(guard, client)
        coverage.append(("scope-validation", "completed",
                         f"scope={guard.base}; allow_private={allow_private}"))
        for cid in prof["checks"]:
            if cancel_event is not None and cancel_event.is_set():
                coverage.append(("orchestrator", "not-tested", "scan cancelled by user"))
                store.save_coverage(sid, coverage)
                store.finish_scan(sid, "cancelled")
                return store.get_scan(sid)
            check = REGISTRY[cid]
            try:
                res = check.fn(ctx)
                findings.extend(res)
                coverage.append((cid, "completed", f"{len(res)} finding record(s)"))
            except Exception as e:
                coverage.append((cid, "failed", f"{type(e).__name__}: {e}"))
        if profile >= 2 and guard.base.startswith("https"):
            from .adapters import testssl_available
            if testssl_available():
                coverage.append(("testssl-tls-deep", "not-tested",
                    "testssl.sh is installed but DISABLED: as a subprocess it does its own DNS/networking outside the pinned, scope-guarded transport. Kept unavailable until it can be pinned to validated IPs (e.g. forced-IP mode) rather than bypass SSRF defenses."))
            else:
                coverage.append(("testssl-tls-deep", "not-tested", "testssl.sh not installed"))
        if profile == 2:
            pages = crawl(ctx)
            pf = page_findings(pages)
            findings.extend(pf)
            coverage.append(("same-origin-crawl", "completed",
                             f"{len(pages)} page(s) crawled, {len(pf)} page-level record(s)"))
            coverage.append(("active-tests-nuclei-zap", "not-tested",
                             "Nuclei/ZAP binaries not installed; active vulnerability tests absent from this profile subset"))
        for pid, p in PROFILES.items():
            if not p["available"]:
                coverage.append((f"profile-{pid}", "not-tested",
                                 p["unavailable_reason"]))
        # dedupe: same check, same asset, same description (crawl overlaps baseline)
        seen_keys, unique = set(), []
        for f in findings:
            key = (f.check_id, f.asset, f.description)
            if key not in seen_keys:
                seen_keys.add(key)
                unique.append(f)
        if len(unique) != len(findings):
            coverage.append(("dedupe", "completed",
                             f"{len(findings) - len(unique)} duplicate record(s) merged"))
        findings = unique
        for f in findings:
            store.save_finding(sid, f)
        store.save_coverage(sid, coverage)
        store.finish_scan(sid, "complete")
    except ScopeError as e:
        store.save_coverage(sid, coverage + [("scope-validation", "failed", str(e))])
        store.finish_scan(sid, "failed", error=str(e))
    except Exception as e:
        store.save_coverage(sid, coverage + [("orchestrator", "failed",
                                              f"{type(e).__name__}: {e}")])
        store.finish_scan(sid, "failed", error=f"{type(e).__name__}: {e}")
        traceback.print_exc()
    return store.get_scan(sid)
