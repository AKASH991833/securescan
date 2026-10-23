"""Background scan job queue with cancellation (in-process, thread-based).
Single-user local prototype: no Redis dependency. Thread-safe; the pinned
transport has no global state, so concurrent jobs are safe."""
from __future__ import annotations
import threading, time, uuid

class JobManager:
    def __init__(self, store):
        self.store = store
        self.jobs = {}          # job_id -> info dict
        self._lock = threading.Lock()

    def submit(self, target, profile, allow_private=False, budget=60, org_id="local"):
        jid = "job-" + uuid.uuid4().hex[:10]
        cancel = threading.Event()
        info = {"id": jid, "target": target, "profile": profile,
                "status": "queued", "scan_id": None, "cancel": cancel,
                "created": time.time(), "error": None}
        with self._lock:
            self.jobs[jid] = info
        th = threading.Thread(target=self._run, args=(info, allow_private, budget, org_id),
                              daemon=True)
        info["thread"] = th
        th.start()
        return jid

    def _run(self, info, allow_private, budget, org_id="local"):
        from .orchestrator import run_scan
        info["status"] = "running"
        try:
            result = run_scan(info["target"], info["profile"], self.store,
                              allow_private=allow_private, budget=budget,
                              cancel_event=info["cancel"], org_id=org_id)
            info["scan_id"] = result["scan"]["id"]
            info["status"] = ("cancelled" if info["cancel"].is_set()
                              else result["scan"]["status"])
        except Exception as e:
            info["status"] = "failed"
            info["error"] = f"{type(e).__name__}: {e}"

    def cancel(self, jid):
        with self._lock:
            info = self.jobs.get(jid)
        if not info:
            return False
        info["cancel"].set()
        if info["status"] == "queued":
            info["status"] = "cancelled"
        return True

    def get(self, jid):
        info = self.jobs.get(jid)
        if not info:
            return None
        return {k: v for k, v in info.items() if k not in ("cancel", "thread")}

    def list(self):
        return [self.get(j) for j in self.jobs]
