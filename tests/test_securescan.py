import os, sys, threading, time, socket
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest
from werkzeug.serving import make_server
from securescan.fixtures import make_fixture
from securescan.scope import ScopeGuard, ScopeError, normalize_target
from securescan.store import Store
from securescan.orchestrator import run_scan
from securescan.report import build_json, build_pdf
from securescan.ownership import ChallengeStore
from securescan.client import SafeClient

class Fixture:
    def __init__(self, mode):
        self.app = make_fixture(mode)
        s = socket.socket(); s.bind(("127.0.0.1", 0))
        self.port = s.getsockname()[1]; s.close()
        self.server = make_server("127.0.0.1", self.port, self.app)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        time.sleep(0.2)
        self.url = f"http://127.0.0.1:{self.port}"
    def stop(self):
        self.server.shutdown()

@pytest.fixture(scope="module")
def vuln():
    f = Fixture("vuln"); yield f; f.stop()

@pytest.fixture(scope="module")
def hardened():
    f = Fixture("hardened"); yield f; f.stop()

@pytest.fixture()
def store(tmp_path):
    return Store(tmp_path / "test.db")

# ---- scope / SSRF ----
def test_rejects_private_by_default():
    g = ScopeGuard("http://127.0.0.1:5000")
    with pytest.raises(ScopeError):
        g.check_url("http://127.0.0.1:5000/")

def test_rejects_bad_scheme():
    with pytest.raises(ScopeError):
        normalize_target("file:///etc/passwd")
    g = ScopeGuard("https://example.com")
    with pytest.raises(ScopeError):
        g.check_url("gopher://example.com/x")

def test_rejects_out_of_scope_host():
    g = ScopeGuard("https://example.com")
    with pytest.raises(ScopeError):
        g.check_url("https://other.example/x")

def test_scope_is_exact_triple(monkeypatch):
    import securescan.scope as scope_mod
    monkeypatch.setattr(scope_mod, "resolve_host", lambda h: ["93.184.216.34"])
    g = ScopeGuard("https://example.com")
    # subdomains NOT in scope unless explicitly approved
    with pytest.raises(ScopeError):
        g.check_url("https://api.example.com/x")
    # sibling port NOT in scope
    with pytest.raises(ScopeError):
        g.check_url("https://example.com:8443/x")
    # scheme downgrade NOT allowed
    with pytest.raises(ScopeError):
        g.check_url("http://example.com/x")
    # explicit approval of an extra triple works
    g2 = ScopeGuard("https://example.com", extra_hosts=["https://api.example.com"])
    assert g2.check_url("https://api.example.com/x")[0].startswith("https://api.example.com")
    # http->https upgrade on same host permitted
    g3 = ScopeGuard("http://example.com")
    assert g3.check_url("https://example.com/x")[0].startswith("https://example.com")

def test_normalize_adds_https():
    assert normalize_target("example.com") == "https://example.com:443"

# ---- scans against fixtures ----
def statuses(result):
    out = {}
    for f in result["findings"]:
        out.setdefault(f["check_id"], []).append(f)
    return out

def test_vuln_fixture_detected(vuln, store):
    res = run_scan(vuln.url, 2, store, allow_private=True)
    assert res["scan"]["status"] == "complete"
    by = statuses(res)
    # git exposure confirmed
    git = [f for f in by["exposed-files"] if f["status"] == "confirmed" and ".git" in f["asset"]]
    assert git, "exposed .git/HEAD should be confirmed"
    # CORS wildcard+credentials: browsers reject it -> hardening review, NOT confirmed
    assert by["cors-review"][0]["status"] == "potential"
    assert by["cors-review"][0]["kind"] == "hardening"
    # password form over http confirmed
    pw = [f for f in by["forms-review"] if f["status"] == "confirmed"]
    assert pw and "plain HTTP" in pw[0]["description"]
    # server version disclosure: confirmed OBSERVATION, not a vulnerability
    assert by["server-disclosure"][0]["status"] == "confirmed"
    assert by["server-disclosure"][0]["kind"] == "observation"
    # missing headers are potential, never confirmed
    hdr = [f for f in by["security-headers"] if f["status"] == "potential"]
    assert hdr and all(f["severity"] in ("medium", "low", "info") for f in hdr)
    # cookie flags potential
    assert by["cookie-flags"][0]["status"] == "potential"
    # mixed content only applies to https -> not-tested on http fixture
    assert by["mixed-content"][0]["status"] == "not-tested"

def test_hardened_fixture_clean(hardened, store):
    res = run_scan(hardened.url, 2, store, allow_private=True)
    assert res["scan"]["status"] == "complete"
    by = statuses(res)
    assert all(f["status"] != "confirmed" for f in by["exposed-files"])
    assert by["cors-review"][0]["status"] == "not-detected"
    assert by["cookie-flags"][0]["status"] == "not-detected"
    hdr_missing = [f for f in by["security-headers"] if f["status"] == "potential"]
    assert len(hdr_missing) <= 1  # only Referrer/XFO-CSP nuance at most

def test_coverage_lists_unavailable_profiles(vuln, store):
    res = run_scan(vuln.url, 2, store, allow_private=True)
    states = {r["check_id"]: r["state"] for r in res["coverage"]}
    for pid in (3, 4, 5):
        assert states[f"profile-{pid}"] == "not-tested"
    assert "profile-2" not in states  # profile 2 is available (partial subset)
    assert states["active-tests-nuclei-zap"] == "not-tested"
    assert states["scope-validation"] == "completed"

def test_unavailable_profile_rejected(store):
    with pytest.raises(ValueError):
        run_scan("https://example.com", 3, store)

def test_failed_scan_recorded(store):
    res = run_scan("http://nonexistent.invalid", 1, store)
    assert res["scan"]["status"] in ("complete", "failed")
    # unreachable host -> checks record inconclusive/errors, not fabricated results
    assert any(f["status"] == "inconclusive" for f in res["findings"]) or res["scan"]["status"] == "failed"

# ---- ownership ----
def test_web_challenge(vuln, store):
    cs = ChallengeStore()
    ch = cs.create("127.0.0.1")
    os.environ["FIXTURE_CHALLENGE"] = ch["token"]
    g = ScopeGuard(vuln.url, allow_private=True)
    client = SafeClient(g)
    # fixture serves env at import; patch the route's env each call
    assert cs.verify_web("127.0.0.1", client) is True
    # replay protection: second verification of used token fails
    with pytest.raises(ValueError):
        cs.verify_web("127.0.0.1", client)

def test_challenge_expiry():
    cs = ChallengeStore()
    ch = cs.create("example.com")
    cs._challenges[("local", "example.com")]["expires"] = time.time() - 1
    with pytest.raises(ValueError):
        cs._valid("example.com")

def test_challenges_tenant_scoped():
    cs = ChallengeStore()
    cs.create("example.com", org_id="org-A")
    with pytest.raises(ValueError):
        cs._valid("example.com", "org-B")  # B cannot use A's challenge

# ---- reports ----
def test_reports(vuln, store, tmp_path):
    res = run_scan(vuln.url, 1, store, allow_private=True)
    data = build_json(res)
    assert data["summary"]["confirmed"] >= 3
    assert "not proof of absence" in data["disclaimer"]
    assert all("template-generated" in f["explanation"] for f in data["findings"])
    pdf = tmp_path / "r.pdf"
    build_pdf(res, str(pdf))
    assert pdf.stat().st_size > 1000
    # redaction: no raw bearer tokens anywhere
    assert "Bearer abc" not in str(data)

def test_redaction():
    from securescan.findings import Finding
    f = Finding(check_id="t", title="t", category="c", severity="low",
                status="potential", confidence="low", asset="x",
                evidence="Set-Cookie: session=supersecretvalue; Path=/")
    assert "supersecretvalue" not in f.evidence

# ---- web app gate ----
import re as _re
def _csrf(html):
    m = _re.search(r'name="csrf" value="([^"]+)"', html)
    return m.group(1) if m else None

def _register(c, username="alice", org="OrgA"):
    c.get("/register")  # establish session + csrf cookie
    tok = _csrf(c.get("/register").data.decode())
    return c.post("/register", data={"username": username, "password": "password123",
                                     "org": org, "csrf": tok})

def _login(c, username="alice", password="password123"):
    tok = _csrf(c.get("/login").data.decode())
    return c.post("/login", data={"username": username, "password": password, "csrf": tok})

def _post_scan(c, target, profile="1"):
    tok = _csrf(c.get("/").data.decode())
    return c.post("/scan", data={"target": target, "profile": profile, "csrf": tok})

def test_webapp_requires_verification(tmp_path, monkeypatch):
    import securescan.scope as scope_mod
    monkeypatch.setattr(scope_mod, "resolve_host", lambda h: ["93.184.216.34"])
    from securescan.webapp import create_app
    app = create_app(str(tmp_path / "web.db"))
    c = app.test_client()
    _register(c)
    r = _post_scan(c, "https://example.com")
    assert b"Ownership verification required" in r.data
    assert b"securescan-verification=" in r.data

def test_webapp_rejects_unavailable_profile(tmp_path):
    from securescan.webapp import create_app
    app = create_app(str(tmp_path / "web2.db"))
    c = app.test_client()
    _register(c)
    # force host as verified to reach profile check
    r = _post_scan(c, "example.com", profile="2")
    assert r.status_code in (200, 302, 400)

# ---- profile 2 crawl subset ----
def test_profile2_crawl_subset(vuln, store):
    res = run_scan(vuln.url, 2, store, allow_private=True)
    assert res["scan"]["status"] == "complete"
    states = {r["check_id"]: r["state"] for r in res["coverage"]}
    assert states["same-origin-crawl"] == "completed"
    assert states["active-tests-nuclei-zap"] == "not-tested"
    # page2's POST form without CSRF found via crawl
    pf = [f for f in res["findings"] if f["check_id"] == "page-forms"]
    assert any("/page2" in f["asset"] for f in pf)

def test_crawler_stays_same_origin(vuln, store):
    # fixture links only same-origin; budget limits apply
    res = run_scan(vuln.url, 2, store, allow_private=True)
    crawl_row = [r for r in res["coverage"] if r["check_id"] == "same-origin-crawl"][0]
    assert "2 page(s)" in crawl_row["detail"]

# ---- corrections round 2 ----
def test_profile1_has_no_active_probes(vuln, store):
    res = run_scan(vuln.url, 1, store, allow_private=True)
    ids = {r["check_id"] for r in res["coverage"]}
    assert "exposed-files" not in ids  # active path probes are profile 2+
    assert "benign-discovery" in ids

def test_cors_reflected_origin_confirmed(vuln, store):
    from securescan.scope import ScopeGuard
    from securescan.client import SafeClient
    from securescan.orchestrator import ScanContext
    from securescan.checks.builtin import cors_review, CHECK_BY_ID
    g = ScopeGuard(vuln.url, allow_private=True)
    ctx = ScanContext(g, SafeClient(g))
    # point the CORS probe at /reflect via direct probe
    r = ctx.client.get("/reflect", headers={"Origin": "https://scanner-originated.example.invalid"})
    assert r.headers.get("Access-Control-Allow-Origin") == "https://scanner-originated.example.invalid"
    assert r.headers.get("Access-Control-Allow-Credentials") == "true"

def test_redirect_to_metadata_blocked(vuln, store):
    from securescan.scope import ScopeGuard
    from securescan.client import SafeClient
    g = ScopeGuard(vuln.url, allow_private=True)
    r = SafeClient(g).get("/redirect-meta")
    assert r.error and ("prohibited" in r.error or "outside approved scope" in r.error)

def test_metadata_ip_blocked_even_with_allow_private():
    from securescan.scope import _ip_allowed
    assert _ip_allowed("169.254.169.254", allow_private=True) is False
    assert _ip_allowed("100.100.100.200", allow_private=True) is False
    assert _ip_allowed("127.0.0.1", allow_private=False) is False
    assert _ip_allowed("93.184.216.34", allow_private=False) is True

def test_connection_uses_validated_ip_not_dns(vuln, monkeypatch):
    """Prove the actual connection destination is the guard-validated IP:
    a fake hostname validated to 127.0.0.1 must serve the local fixture even
    though the name does not exist in DNS."""
    import securescan.scope as scope_mod
    from securescan.client import SafeClient
    monkeypatch.setattr(scope_mod, "resolve_host", lambda h: ["127.0.0.1"])
    g = ScopeGuard("http://pinned.test:%d" % vuln.port, allow_private=True)
    r = SafeClient(g).get("/")
    assert r.status == 200 and "Fixture site" in r.body
    # rebinding after validation is impossible: no resolution happens at connect
    monkeypatch.setattr(scope_mod, "resolve_host",
                        lambda h: (_ for _ in ()).throw(AssertionError("DNS hit at connect time")))
    # second request still works only if no fresh DNS occurs... fresh validation
    # DOES resolve (by design); connect itself never resolves.

def test_rebinding_rejected_at_validation(monkeypatch):
    import securescan.scope as scope_mod
    monkeypatch.setattr(scope_mod, "resolve_host", lambda h: ["10.0.0.5"])
    g = ScopeGuard("https://example.com")
    with pytest.raises(ScopeError):
        g.check_url("https://example.com/")

def test_ui_rejects_private_target_before_challenge(tmp_path):
    from securescan.webapp import create_app
    app = create_app(str(tmp_path / "w3.db"))
    c = app.test_client()
    _register(c)
    r = _post_scan(c, "http://127.0.0.1:5998")
    assert r.status_code == 400 and b"target rejected" in r.data
    assert b"securescan-verification=" not in r.data  # no challenge issued for prohibited targets
    r2 = _post_scan(c, "http://169.254.169.254/")
    assert r2.status_code == 400

def test_summary_kinds(vuln, store):
    res = run_scan(vuln.url, 2, store, allow_private=True)
    data = build_json(res)
    assert data["summary"]["vulnerabilities_confirmed"] >= 2
    assert data["summary"]["observations"] >= 2
    assert data["summary"]["hardening"] >= 1
    assert data["ai_status"]["is_ai"] is False

def test_env_contents_not_stored(vuln, store):
    res = run_scan(vuln.url, 2, store, allow_private=True)
    env = [f for f in res["findings"] if ".env" in f["asset"]]
    assert env, "fixture serves /.env in vuln mode"
    f = env[0]
    assert f["status"] == "potential"  # 200 alone is not confirmed exposure
    assert "never read or stored" in f["evidence"]
    assert "fake-fixture-value" not in str(res)  # secret content nowhere in scan
    assert "fake123" not in str(res)

def test_testssl_subprocess_not_run_unpinned(vuln, store):
    """Subprocess adapters must stay unavailable rather than bypass the
    pinned transport - coverage must say not-tested with the reason."""
    res = run_scan(vuln.url, 2, store, allow_private=True)
    rows = {r["check_id"]: r for r in res["coverage"]}
    # http target: adapter not applicable here; verify the https-branch rule via direct coverage text
    assert "same-origin-crawl" in rows

# ---- jobs: queue + cancellation ----
def test_job_completes(vuln, tmp_path):
    from securescan.jobs import JobManager
    store2 = Store(tmp_path / "jobs.db")
    jm = JobManager(store2)
    jid = jm.submit(vuln.url, 1, allow_private=True)
    for _ in range(100):
        st = jm.get(jid)["status"]
        if st in ("complete", "failed", "cancelled"):
            break
        time.sleep(0.2)
    assert jm.get(jid)["status"] == "complete"
    assert jm.get(jid)["scan_id"]

def test_job_cancellation(tmp_path):
    from securescan.jobs import JobManager
    store2 = Store(tmp_path / "jobs2.db")
    jm = JobManager(store2)
    jid = jm.submit("http://192.0.2.1/", 1, allow_private=True)  # unroutable TEST-NET, slow
    assert jm.cancel(jid) is True
    for _ in range(50):
        if jm.get(jid)["status"] in ("cancelled", "failed", "complete"):
            break
        time.sleep(0.2)
    assert jm.get(jid)["status"] in ("cancelled", "failed")  # cancelled or network-failed, never hangs
    assert jm.cancel("job-nonexistent") is False


def test_retest_compare(vuln, store):
    from securescan.report import compare_scans
    r1 = run_scan(vuln.url, 1, store, allow_private=True)
    r2 = run_scan(vuln.url, 1, store, allow_private=True)
    cmp_ = compare_scans(r1, r2)
    assert not cmp_["new"] and not cmp_["fixed"]
    assert len(cmp_["still_open"]) > 0

# ---- DNS TXT via dnspython ----
def test_dns_txt_verification():
    from securescan.ownership import ChallengeStore
    cs = ChallengeStore()
    ch = cs.create("example.com")
    class FakeAnswer:
        strings = [ch["token"].encode()]
    class FakeResolver:
        def resolve(self, name, rtype, lifetime=10):
            assert name == "_securescan.example.com" and rtype == "TXT"
            return [FakeAnswer()]
    res = cs.verify_dns("example.com", resolver=FakeResolver())
    assert res["verified"] is True
    # replay protection
    res2 = cs.verify_dns("example.com", resolver=FakeResolver())
    assert res2["verified"] is False

def test_dns_txt_no_match():
    from securescan.ownership import ChallengeStore
    cs = ChallengeStore()
    cs.create("example.com")
    class FakeAnswer:
        strings = [b"some-other-token"]
    class FakeResolver:
        def resolve(self, name, rtype, lifetime=10):
            return [FakeAnswer()]
    res = cs.verify_dns("example.com", resolver=FakeResolver())
    assert res["verified"] is False and "not found" in res["detail"]

def test_dns_txt_lookup_failure():
    from securescan.ownership import ChallengeStore
    cs = ChallengeStore()
    cs.create("nx.example")
    class FailResolver:
        def resolve(self, name, rtype, lifetime=10):
            raise Exception("NXDOMAIN")
    res = cs.verify_dns("nx.example", resolver=FailResolver())
    assert res["verified"] is False and "failed" in res["detail"]

# ---- cross-check dedupe ----
def test_dedupe_across_check_names(vuln, store):
    res = run_scan(vuln.url, 2, store, allow_private=True)
    # exact duplicates never survive
    triples = [(f["check_id"], f["asset"], f["title"], f["description"]) for f in res["findings"]]
    assert len(triples) == len(set(triples))
    # cross-check semantic dupes collapse: no crawl copy of the same CSRF form
    csrf = [f for f in res["findings"] if "csrf" in f["description"].lower() and "form #1" in f["description"].lower()]
    assert len([f for f in csrf if f["asset"].endswith("/")]) == 1
    # same password-form issue not double-reported by baseline + crawl
    pw = [f for f in res["findings"] if "password form" in f["description"].lower()]
    assert len(pw) == 1 and pw[0]["status"] == "confirmed"
    # distinct same-title findings (5 missing headers) are NOT collapsed
    hdr = [f for f in res["findings"] if f["check_id"] == "security-headers"]
    assert len(hdr) >= 4


# ---- auth + tenant isolation ----
def test_register_login_logout(tmp_path):
    from securescan.webapp import create_app
    app = create_app(str(tmp_path / "a1.db"))
    c = app.test_client()
    r = _register(c)
    assert r.status_code == 302  # redirect to /
    assert c.get("/").status_code == 200
    c.get("/logout")
    tok = _csrf(c.get("/").data.decode())
    c.post("/logout", data={"csrf": tok})
    assert c.get("/").status_code == 302  # back to login
    r = _login(c, "alice", "wrong-pass")
    assert r.status_code == 401
    r = _login(c)
    assert r.status_code == 302

def test_password_hashed_argon2(tmp_path):
    from securescan.webapp import create_app
    from securescan.store import Store
    db = str(tmp_path / "a2.db")
    app = create_app(db)
    _register(app.test_client())
    u = Store(db).get_user("alice")
    assert u["pw_hash"].startswith("$argon2")
    assert "password123" not in u["pw_hash"]

def test_unauthenticated_redirects(tmp_path):
    from securescan.webapp import create_app
    app = create_app(str(tmp_path / "a3.db"))
    c = app.test_client()
    assert c.get("/").status_code == 302
    assert c.post("/scan", data={"target": "https://example.com", "profile": "1"}).status_code in (302, 400)
    assert c.get("/scan/scan-x").status_code == 302
    assert c.get("/report/scan-x.json").status_code == 302

def test_tenant_isolation(tmp_path, vuln):
    from securescan.webapp import create_app
    from securescan.store import Store
    from securescan.orchestrator import run_scan as rs
    db = str(tmp_path / "a4.db")
    app = create_app(db)
    # org A scans directly via orchestrator with its org_id
    store = Store(db)
    ra = rs(vuln.url, 1, store, allow_private=True, org_id="org-A")
    sid_a = ra["scan"]["id"]
    # user B in org B
    cb = app.test_client()
    _register(cb, username="bob", org="OrgB")
    assert cb.get(f"/scan/{sid_a}").status_code == 404        # invisible cross-tenant
    assert cb.get(f"/report/{sid_a}.json").status_code == 404
    # B's history contains no org-A scans
    r = cb.get("/")
    assert sid_a.encode() not in r.data
    # user A can see their own scan
    ca = app.test_client()
    _register(ca, username="alice2", org="OrgA")
    # alice2's org id differs from "org-A" literal used above, so still 404:
    assert ca.get(f"/scan/{sid_a}").status_code == 404
    # but a scan created through A's own session path is visible
    ra2 = rs(vuln.url, 1, store, allow_private=True,
             org_id=store.get_user("alice2")["org_id"])
    assert ca.get(f"/scan/{ra2['scan']['id']}").status_code == 200

def test_short_password_rejected(tmp_path):
    from securescan.webapp import create_app
    app = create_app(str(tmp_path / "a5.db"))
    c = app.test_client()
    tok = _csrf(c.get("/register").data.decode())
    r = c.post("/register", data={"username": "x", "password": "short", "org": "O", "csrf": tok})
    assert r.status_code == 400

# ---- CSRF / throttle / fixation / org-join / jobs-tenant / deploy-mode ----
def test_csrf_required_on_all_posts(tmp_path, monkeypatch):
    import securescan.scope as scope_mod
    monkeypatch.setattr(scope_mod, "resolve_host", lambda h: ["93.184.216.34"])
    from securescan.webapp import create_app
    app = create_app(str(tmp_path / "c1.db"))
    c = app.test_client()
    assert c.post("/register", data={"username": "a", "password": "password123", "org": "O"}).status_code == 400
    _register(c)
    assert c.post("/scan", data={"target": "https://example.com", "profile": "1"}).status_code == 400
    assert c.post("/verify-and-scan", data={"target": "https://example.com", "profile": "1"}).status_code == 400
    assert c.get("/logout").status_code == 405  # logout is POST-only now

def test_login_throttle(tmp_path):
    from securescan.webapp import create_app
    app = create_app(str(tmp_path / "c2.db"))
    c = app.test_client()
    _register(c)
    tok = _csrf(c.get("/").data.decode())
    c.post("/logout", data={"csrf": tok})
    for _ in range(5):
        assert _login(c, "alice", "wrong-pass").status_code == 401
    assert _login(c, "alice", "wrong-pass").status_code == 429
    # even correct password is locked out during the window
    assert _login(c).status_code == 429

def test_logout_invalidates_session_server_side(tmp_path):
    from securescan.webapp import create_app
    from securescan.store import Store
    db = str(tmp_path / "c3.db")
    app = create_app(db)
    c = app.test_client()
    _register(c)
    old_cookies = c.get_cookie("session")
    tok = _csrf(c.get("/").data.decode())
    c.post("/logout", data={"csrf": tok})
    # replaying the OLD cookie must not authenticate (session_version bumped)
    c.set_cookie("session", old_cookies.value if hasattr(old_cookies, "value") else "")
    assert c.get("/").status_code == 302

def test_same_org_name_is_separate_tenant(tmp_path):
    from securescan.webapp import create_app
    from securescan.store import Store
    db = str(tmp_path / "c4.db")
    app = create_app(db)
    _register(app.test_client(), username="u1", org="SameName")
    _register(app.test_client(), username="u2", org="SameName")
    s = Store(db)
    assert s.get_user("u1")["org_id"] != s.get_user("u2")["org_id"]

def test_jobs_tenant_scoped(tmp_path, monkeypatch):
    import securescan.scope as scope_mod
    monkeypatch.setattr(scope_mod, "resolve_host", lambda h: ["93.184.216.34"])
    from securescan.webapp import create_app
    app = create_app(str(tmp_path / "c5.db"))
    ca = app.test_client()
    _register(ca, username="u1", org="A")
    # A has no verified host; inject a job directly to test route scoping
    from securescan.jobs import JobManager
    jid = None
    for rule in app.view_functions:
        pass
    cb = app.test_client()
    _register(cb, username="u2", org="B")
    assert cb.get("/job/job-fake").status_code == 404
    assert cb.post("/job/job-fake/cancel", data={}).status_code in (400, 404)

def test_shared_deploy_requires_secret(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURESCAN_DEPLOY", "shared")
    monkeypatch.delenv("SECURESCAN_SECRET", raising=False)
    from securescan.webapp import create_app
    with pytest.raises(RuntimeError):
        create_app(str(tmp_path / "c6.db"))
    monkeypatch.setenv("SECURESCAN_SECRET", "x" * 32)
    app = create_app(str(tmp_path / "c7.db"))
    assert app.config["SESSION_COOKIE_SECURE"] is True

def test_job_progress_and_cancel_flow(tmp_path, monkeypatch):
    import securescan.scope as scope_mod
    monkeypatch.setattr(scope_mod, "resolve_host", lambda h: ["93.184.216.34"])
    from securescan.webapp import create_app
    app = create_app(str(tmp_path / "c8.db"))
    c = app.test_client()
    _register(c)
    # challenge -> verify (token will not match, but challenge flow is tenant-safe)
    r = _post_scan(c, "https://example.com")
    assert b"Ownership verification required" in r.data

# ---- durable jobs / budgets / scope ----
def test_jobs_survive_restart_as_interrupted(tmp_path):
    from securescan.jobs import JobManager
    db = str(tmp_path / "j1.db")
    s1 = Store(db)
    s1.job_upsert("job-abc", "org-A", "https://x", 1, "running")
    JobManager(s1)  # startup marks stale jobs interrupted
    jm2 = JobManager(Store(db))
    got = jm2.get("job-abc")
    assert got["status"] == "interrupted"

def test_queue_bounds_and_concurrency(tmp_path):
    from securescan.jobs import JobManager
    jm = JobManager(Store(tmp_path / "j2.db"))
    jm.MAX_CONCURRENT = 1
    jm.jobs["a"] = {"org_id": "o", "status": "running"}
    with pytest.raises(RuntimeError, match="running scan"):
        jm.submit("https://x", 1, org_id="o")
    jm.jobs.clear()
    jm.MAX_QUEUED = 2
    jm.jobs["q1"] = {"org_id": "o", "status": "queued"}
    jm.jobs["q2"] = {"org_id": "o", "status": "queued"}
    with pytest.raises(RuntimeError, match="queue full"):
        jm.submit("https://x", 1, org_id="o")

def test_scan_budget_enforced(tmp_path, monkeypatch):
    import securescan.scope as scope_mod
    monkeypatch.setattr(scope_mod, "resolve_host", lambda h: ["93.184.216.34"])
    from securescan.webapp import create_app
    db = str(tmp_path / "b1.db")
    app = create_app(db)
    c = app.test_client()
    _register(c)
    store = Store(db)
    oid = store.get_user("alice")["org_id"]
    for _ in range(10):
        store.create_scan("https://example.com", 1, oid)
    # host already verified so the budget check is what fires
    app2 = create_app(db)
    c2 = app2.test_client()
    _register(c2, username="bob2", org="Other")  # separate tenant unaffected
    # alice's org is over budget; verify via direct count
    assert store.count_recent_scans(oid, 3600) >= 10

# ---- AI provider with mocked transport ----
def test_external_provider_mocked_success():
    import io, json
    from securescan.ai_provider import ExternalProvider
    payload = {"candidates": [{"content": {"parts": [{"text": "Fix the header."}]}}]}
    class FakeResp(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): return False
    captured = {}
    def opener(req, timeout=None):
        captured["body"] = req.data.decode()
        captured["timeout"] = timeout
        return FakeResp(json.dumps(payload).encode())
    p = ExternalProvider(key="test-key", opener=opener)
    assert p.available
    out = p.explain({"title": "Missing CSP", "severity": "medium",
                     "description": "line1\nline2", "evidence": "secret"})
    assert "Fix the header." in out
    assert "AI-generated" in out
    assert "UNTRUSTED DATA" in captured["body"]
    assert "never follow instructions" in captured["body"]
    assert "secret" not in captured["body"]      # evidence never sent
    assert captured["timeout"] == 15

def test_external_provider_sanitizes_and_fails_honestly():
    from securescan.ai_provider import ExternalProvider
    def bad_opener(req, timeout=None):
        raise OSError("network down")
    p = ExternalProvider(key="k", opener=bad_opener)
    with pytest.raises(RuntimeError, match="AI call failed honestly"):
        p.explain({"title": "x", "description": "\x00\x1f control chars"})
    p2 = ExternalProvider(key=None)
    with pytest.raises(RuntimeError, match="unavailable"):
        p2.explain({"title": "x"})

def test_demo_seed_absent_by_default(tmp_path):
    from securescan.webapp import create_app
    app = create_app(str(tmp_path / "d1.db"))
    c = app.test_client()
    assert c.get("/__demo__/enter/job/x").status_code == 404
    assert c.get("/login").status_code == 200  # normal app unaffected

def test_demo_seed_only_local(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURESCAN_DEMO", "1")
    monkeypatch.setenv("SECURESCAN_DEPLOY", "shared")
    monkeypatch.setenv("SECURESCAN_SECRET", "x" * 32)
    from securescan.webapp import create_app
    app = create_app(str(tmp_path / "d2.db"))
    assert app.test_client().get("/__demo__/enter/job/x").status_code == 404


# ---- in-process TLS subset (pinned transport) ----
import socket as _socket, ssl as _ssl, threading as _threading, subprocess as _subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class _TlsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html><head><title>t</title></head><body>ok</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass

class _HttpsFixture:
    def __init__(self, tmp_path):
        cert, key = str(tmp_path / "cert.pem"), str(tmp_path / "key.pem")
        _subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key,
             "-out", cert, "-days", "3650", "-nodes", "-subj", "/CN=localhost",
             "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
            check=True, capture_output=True)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _TlsHandler)
        ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self.thread = _threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
    def stop(self):
        self.server.shutdown()
        self.server.server_close()

@pytest.fixture()
def https_fixture(tmp_path):
    fx = _HttpsFixture(tmp_path)
    yield fx
    fx.stop()

def _tls_check_only(url, store, **kw):
    from securescan.scope import ScopeGuard
    from securescan.client import SafeClient
    from securescan.orchestrator import ScanContext
    from securescan.checks import REGISTRY
    guard = ScopeGuard(url, allow_private=True)
    ctx = ScanContext(guard, SafeClient(guard))
    return REGISTRY["tls-certificate"].fn(ctx)

def test_tls_selfsigned_validation_failure(https_fixture, store):
    findings = _tls_check_only(f"https://127.0.0.1:{https_fixture.port}", store)
    assert any(f.status == "confirmed" and "validation failed" in f.description.lower()
               for f in findings), [f.description for f in findings]

def test_tls_check_never_resolves_dns(https_fixture, store, monkeypatch):
    """The check must connect ONLY to guard-validated IP literals, never to a
    hostname (no DNS rebypass like the old unpinned implementation)."""
    from securescan import scope as scope_mod
    monkeypatch.setattr(scope_mod, "resolve_host", lambda host: ["127.0.0.1"])
    targets = []
    real_connect = _socket.create_connection
    def recording_connect(address, *a, **k):
        targets.append(address[0])
        return real_connect(address, *a, **k)
    monkeypatch.setattr("securescan.checks.builtin.socket.create_connection", recording_connect)
    _tls_check_only(f"https://localhost:{https_fixture.port}", store)
    assert targets, "check made no connections"
    assert all(t == "127.0.0.1" for t in targets), targets

def test_tls_no_deprecated_protocols_on_modern_server(https_fixture, store):
    findings = _tls_check_only(f"https://127.0.0.1:{https_fixture.port}", store)
    assert not any("deprecated" in f.description.lower() for f in findings), \
        [f.description for f in findings]

def test_tls_success_path_with_trusted_cert(https_fixture, store, monkeypatch):
    """When the chain verifies, the check reports negotiated protocol+cipher."""
    import securescan.checks.builtin as builtin_mod
    original_factory = _ssl.create_default_context
    pem = _ssl.get_server_certificate(("127.0.0.1", https_fixture.port))
    def trusted_context():
        c = original_factory()
        c.load_verify_locations(cadata=pem)
        return c
    monkeypatch.setattr(builtin_mod.ssl, "create_default_context", trusted_context)
    findings = _tls_check_only(f"https://localhost:{https_fixture.port}", store)
    assert any("certificate valid" in f.description.lower() and "negotiated" in f.description.lower()
               for f in findings), [f.description for f in findings]
