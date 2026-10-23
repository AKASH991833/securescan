"""SQLite storage: scans, findings, coverage. Free, zero-install DB."""
from __future__ import annotations
import json, sqlite3, time, uuid
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS orgs (
  id TEXT PRIMARY KEY, name TEXT, created_at REAL);
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, username TEXT UNIQUE, pw_hash TEXT, org_id TEXT,
  session_version INTEGER DEFAULT 0, created_at REAL);
CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY, org_id TEXT, target TEXT, profile INTEGER,
  status TEXT, scan_id TEXT, error TEXT, created_at REAL, updated_at REAL);
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY, org_id TEXT, target TEXT, profile INTEGER, status TEXT,
  created_at REAL, finished_at REAL, error TEXT);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY, scan_id TEXT, check_id TEXT, title TEXT, category TEXT,
  severity TEXT, status TEXT, confidence TEXT, asset TEXT, description TEXT,
  evidence TEXT, impact TEXT, remediation TEXT, refs TEXT, cwe TEXT, owasp TEXT,
  preconditions TEXT, kind TEXT, first_seen REAL, last_seen REAL);
CREATE TABLE IF NOT EXISTS coverage (
  scan_id TEXT, check_id TEXT, state TEXT, detail TEXT,
  PRIMARY KEY (scan_id, check_id));
"""

class Store:
    def __init__(self, path="securescan.db"):
        self.path = str(path)
        with self._conn() as c:
            c.executescript(SCHEMA)

    def _conn(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def create_org(self, name):
        oid = "org-" + uuid.uuid4().hex[:10]
        with self._conn() as c:
            c.execute("INSERT INTO orgs VALUES (?,?,?)", (oid, name, time.time()))
        return oid

    def create_user(self, username, pw_hash, org_id):
        uid = "usr-" + uuid.uuid4().hex[:10]
        with self._conn() as c:
            c.execute("INSERT INTO users VALUES (?,?,?,?,?,?)",
                      (uid, username, pw_hash, org_id, 0, time.time()))
        return uid

    def bump_session_version(self, username):
        with self._conn() as c:
            c.execute("UPDATE users SET session_version=session_version+1 WHERE username=?",
                      (username,))

    def get_user(self, username):
        with self._conn() as c:
            r = c.execute("SELECT * FROM users WHERE username=?",
                          (username,)).fetchone()
        return dict(r) if r else None

    def create_scan(self, target, profile, org_id="local"):
        sid = "scan-" + uuid.uuid4().hex[:12]
        with self._conn() as c:
            c.execute("INSERT INTO scans VALUES (?,?,?,?,?,?,?,?)",
                      (sid, org_id, target, profile, "queued", time.time(), None, None))
        return sid

    def finish_scan(self, sid, status="complete", error=None):
        with self._conn() as c:
            c.execute("UPDATE scans SET status=?, finished_at=?, error=? WHERE id=?",
                      (status, time.time(), error, sid))

    def save_finding(self, sid, f):
        d = f.to_dict()
        with self._conn() as c:
            c.execute("""INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                      (d["id"], sid, d["check_id"], d["title"], d["category"],
                       d["severity"], d["status"], d["confidence"], d["asset"],
                       d["description"], d["evidence"], d["impact"], d["remediation"],
                       json.dumps(d["references"]), d["cwe"], d["owasp"],
                       d["preconditions"], d.get("kind","vulnerability"), d["first_seen"], d["last_seen"]))

    def save_coverage(self, sid, rows):
        with self._conn() as c:
            for check_id, state, detail in rows:
                c.execute("INSERT OR REPLACE INTO coverage VALUES (?,?,?,?)",
                          (sid, check_id, state, detail))

    def get_scan(self, sid, org_id=None):
        """Tenant-scoped: org_id given -> returns empty result for other
        tenants' scans (indistinguishable from nonexistent)."""
        with self._conn() as c:
            if org_id is not None:
                scan = c.execute("SELECT * FROM scans WHERE id=? AND org_id=?",
                                 (sid, org_id)).fetchone()
            else:
                scan = c.execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()
            findings = [dict(r) for r in c.execute(
                "SELECT * FROM findings WHERE scan_id=? ORDER BY first_seen", (sid,))]
            cov = [dict(r) for r in c.execute(
                "SELECT * FROM coverage WHERE scan_id=?", (sid,))]
        return {"scan": dict(scan) if scan else None, "findings": findings, "coverage": cov}

    def job_upsert(self, jid, org_id, target, profile, status, scan_id=None, error=None):
        with self._conn() as c:
            c.execute("""INSERT INTO jobs VALUES (?,?,?,?,?,?,?,?,?)
                         ON CONFLICT(id) DO UPDATE SET status=excluded.status,
                         scan_id=excluded.scan_id, error=excluded.error,
                         updated_at=excluded.updated_at""",
                      (jid, org_id, target, profile, status, scan_id, error,
                       time.time(), time.time()))

    def jobs_for_org(self, org_id):
        with self._conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM jobs WHERE org_id=? ORDER BY created_at DESC LIMIT 50",
                (org_id,))]

    def interrupt_stale_jobs(self):
        """On startup: queued/running jobs from a dead process are marked
        interrupted - never silently lost, never shown as running."""
        with self._conn() as c:
            c.execute("UPDATE jobs SET status='interrupted', updated_at=? "
                      "WHERE status IN ('queued','running')", (time.time(),))

    def count_recent_scans(self, org_id, seconds):
        with self._conn() as c:
            return c.execute(
                "SELECT COUNT(*) n FROM scans WHERE org_id=? AND created_at>?",
                (org_id, time.time() - seconds)).fetchone()["n"]

    def count_recent_orgs(self, seconds):
        with self._conn() as c:
            return c.execute(
                "SELECT COUNT(*) n FROM orgs WHERE created_at>?",
                (time.time() - seconds,)).fetchone()["n"]

    def latest_for_target(self, target, n=2):
        with self._conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM scans WHERE target=? ORDER BY created_at DESC LIMIT ?",
                (target, n))]

    def list_scans(self, org_id=None):
        with self._conn() as c:
            if org_id is not None:
                return [dict(r) for r in c.execute(
                    "SELECT * FROM scans WHERE org_id=? ORDER BY created_at DESC LIMIT 50",
                    (org_id,))]
            return [dict(r) for r in c.execute(
                "SELECT * FROM scans ORDER BY created_at DESC LIMIT 50")]
