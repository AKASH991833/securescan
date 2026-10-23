"""Background scan job queue with cancellation.

Thread-based, thread-safe; the pinned transport has no global state so
concurrent jobs are safe. Job records are DURABLE (SQLite jobs table): a
process restart never loses history - stale queued/running jobs are marked
'interrupted' at startup rather than silently disappearing. Live cancel
events are per-process by design (documented). Bounded queue and per-org
concurrency limits protect shared deployments."""
from __future__ import annotations
import threading, time, uuid

class JobManager:
    MAX_QUEUED = 20          # bounded queue
    MAX_CONCURRENT = 2       # running jobs per org
    MAX_RUNTIME = 300        # seconds; exceeded -> auto-cancel

    def __init__(self, store):
        self.store = store
        self.store.interrupt_stale_jobs()
        self.jobs = {}          # job_id -> live info dict (this process)
        self._lock = threading.Lock()

    def running_for_org(self, org_id):
        with self._lock:
            return sum(1 for j in self.jobs.values()
                       if j["org_id"] == org_id and j["status"] == "running")

    def submit(self, target, profile, allow_private=False, budget=60, org_id="local"):
        with self._lock:
            queued = sum(1 for j in self.jobs.values() if j["status"] == "queued")
            running = sum(1 for j in self.jobs.values()
                          if j["org_id"] == org_id and j["status"] == "running")
            if queued >= self.MAX_QUEUED:
                raise RuntimeError("queue full - try again shortly")
            if running >= self.MAX_CONCURRENT:
                raise RuntimeError(f"organization already has {self.MAX_CONCURRENT} running scan(s)")
        jid = "job-" + uuid.uuid4().hex[:10]
        cancel = threading.Event()
        info = {"id": jid, "target": target, "profile": profile, "org_id": org_id,
                "status": "queued", "scan_id": None, "cancel": cancel,
                "created": time.time(), "error": None}
        with self._lock:
            self.jobs[jid] = info
        self.store.job_upsert(jid, org_id, target, profile, "queued")
        th = threading.Thread(target=self._run, args=(info, allow_private, budget, org_id),
                              daemon=True)
        info["thread"] = th
        th.start()
        return jid

    def _run(self, info, allow_private, budget, org_id="local"):
        from .orchestrator import run_scan
        info["status"] = "running"
        self.store.job_upsert(info["id"], org_id, info["target"], info["profile"],
                              "running")
        timer = threading.Timer(self.MAX_RUNTIME, info["cancel"].set)
        timer.start()
        try:
            result = run_scan(info["target"], info["profile"], self.store,
                              allow_private=allow_private, budget=budget,
                              cancel_event=info["cancel"], org_id=org_id)
            info["scan_id"] = result["scan"]["id"]
            if info["cancel"].is_set() and result["scan"]["status"] != "cancelled":
                info["status"] = "failed"
                info["error"] = "job exceeded max runtime"
            else:
                info["status"] = ("cancelled" if info["cancel"].is_set()
                                  else result["scan"]["status"])
                info["error"] = result["scan"]["error"]
        except Exception as e:
            info["status"] = "failed"
            info["error"] = f"{type(e).__name__}: {e}"
        finally:
            timer.cancel()
        self.store.job_upsert(info["id"], org_id, info["target"], info["profile"],
                              info["status"], info["scan_id"], info["error"])

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
        if info:
            return {k: v for k, v in info.items() if k not in ("cancel", "thread")}
        # fall back to durable record (e.g. after a restart)
        with self.store._conn() as c:
            r = c.execute("SELECT * FROM jobs WHERE id=?", (jid,)).fetchone()
        if not r:
            return None
        d = dict(r)
        return {"id": d["id"], "target": d["target"], "profile": d["profile"],
                "org_id": d["org_id"], "status": d["status"],
                "scan_id": d["scan_id"], "error": d["error"], "created": d["created_at"]}

    def list(self):
        return [self.get(j) for j in self.jobs]
