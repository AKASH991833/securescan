"""Dark-console web UI (English). Local prototype: synchronous scans against
targets the operator is authorized to test. allow_private is NOT set here, so
user-entered targets can never hit localhost/private addresses."""
import functools, os, secrets, time as time_mod
from urllib.parse import urlparse
from flask import Flask, request, render_template_string, abort, session, redirect
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from .store import Store
from .orchestrator import run_scan
from .profiles import PROFILES, external_tools_status
from .report import build_json
from .ownership import ChallengeStore
from .scope import ScopeGuard, ScopeError, normalize_target
from .client import SafeClient

PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>SecureScan</title>
<style>
*{box-sizing:border-box}
body{background:#0b0f14;color:#c9e4ca;font-family:ui-monospace,Menlo,Consolas,monospace;margin:0;padding:1rem;max-width:1100px;margin:0 auto;overflow-x:hidden}
h1{color:#39d353;letter-spacing:.12em;font-size:1.4rem} h2{color:#7ee787;border-bottom:1px solid #1d2b23;padding-bottom:.3rem;font-size:1.05rem}
.panel{background:#0e151c;border:1px solid #1d2b23;border-radius:8px;padding:1rem;margin:1rem 0;overflow-wrap:anywhere}
input,select,button{background:#0e151c;color:#c9e4ca;border:1px solid #2ea043;border-radius:6px;padding:.5rem .6rem;font-family:inherit;font-size:.85rem;max-width:100%}
form.scanform{display:flex;gap:.5rem;flex-wrap:wrap}
form.scanform input{flex:1 1 220px;min-width:0}
form.scanform select{flex:1 1 200px;min-width:0}
button{background:#12351c;cursor:pointer} button:hover{background:#1a4d27}
table{border-collapse:collapse;width:100%;table-layout:fixed}
td,th{border:1px solid #1d2b23;padding:.4rem .5rem;font-size:.8rem;text-align:left;vertical-align:top;overflow-wrap:anywhere}
.chip{display:inline-block;padding:.1rem .5rem;border-radius:10px;font-size:.72rem;font-weight:bold;margin:.05rem 0}
.confirmed{background:#5c1d1d;color:#ffb3b3}.potential{background:#5c4a1d;color:#ffe1a1}
.inconclusive{background:#3a3a3a;color:#ccc}.not-detected{background:#12351c;color:#7ee787}
.failed{background:#5c1d3a;color:#ffb3d9}.completed{background:#12351c;color:#7ee787}
.not-tested{background:#3a3a3a;color:#bbb}
.kind-vulnerability{background:#3d1520;color:#ff9db0}.kind-hardening{background:#3a2f14;color:#e8c97a}.kind-observation{background:#16304a;color:#8fc7ff}
.sev-critical,.sev-high{color:#ff7b72;font-weight:bold}.sev-medium{color:#e8b339}.sev-low{color:#79b8ff}.sev-info{color:#8b949e}
.warn{color:#e8b339}.demo{background:#5c4a1d;color:#ffe1a1;padding:.2rem .6rem;border-radius:4px;font-size:.75rem;display:inline-block}
a{color:#58a6ff} pre{white-space:pre-wrap;font-size:.75rem;color:#9fb8a4;margin:0}
@media (max-width: 640px) {
  body{padding:.6rem}
  table.findings, table.findings tbody, table.findings tr, table.findings td{display:block;width:100%}
  table.findings thead{display:none}
  table.findings tr{border:1px solid #1d2b23;border-radius:8px;margin-bottom:.7rem;padding:.4rem;background:#0e151c}
  table.findings td{border:none;padding:.25rem .3rem}
  table.findings td::before{content:attr(data-h);display:block;color:#5f7a68;font-size:.68rem;text-transform:uppercase}
  table.plain, table.plain tbody, table.plain tr, table.plain td{display:block;width:100%}
  table.plain thead{display:none}
  table.plain td{border:none;border-bottom:1px solid #16202a}
}
</style></head><body>
<h1>SECURESCAN</h1>
{% if session.get("user") %}<small>signed in as {{ session.get("user") }} - <form method="post" action="/logout" style="display:inline"><input type="hidden" name="csrf" value="{{ csrf }}"><button type="submit" style="padding:.1rem .5rem;font-size:.75rem">logout</button></form></small><br>{% endif %}
<span class="demo">LOCAL PROTOTYPE - profile 1 (passive) + profile 2 subset (crawl, path probes) implemented; testssl adapter DISABLED (subprocess would bypass SSRF guard); profiles 3-5 unavailable</span>
<div class="panel">
<form method="post" action="/scan" class="scanform">
<input type="hidden" name="csrf" value="{{ csrf }}">
<input name="target" size="42" placeholder="https://site-you-own.example" required>
<select name="profile">
{% for pid,p in profiles.items() %}
<option value="{{pid}}" {% if not p.available %}disabled{% endif %}>Profile {{pid}} - {{p.name}}{% if not p.available %} (unavailable){% endif %}</option>
{% endfor %}
</select>
<button type="submit">Start scan</button>
</form>
<p class="warn">Only scan systems you own or are explicitly authorized to test. Ownership verification is required before a scan.</p>
</div>

{% if challenge %}
<div class="panel">
<h2>Ownership verification required</h2>
<p>Before scanning <b>{{ challenge.host }}</b>, prove you control it. Place this exact token at
<b>{{ challenge.host }}/.well-known/securescan-verification.txt</b> (web challenge):</p>
<pre>{{ challenge.token }}</pre>
<p>Expires in {{ challenge.expires_in }}s, single-use. Then:</p>
<form method="post" action="/verify-and-scan">
<input type="hidden" name="csrf" value="{{ csrf }}">
<input type="hidden" name="target" value="{{ target }}">
<input type="hidden" name="profile" value="{{ profile }}">
<button type="submit">I placed the file - verify and scan</button>
</form>
{% if verify_error %}<p class="failed chip">verification failed</p> {{ verify_error }}{% endif %}
</div>
{% endif %}
{% if result %}
<h2>Scan {{ result.scan.id }} - {{ result.scan.status }}</h2>
<div class="panel">Target: {{ result.scan.target }} | Profile {{ result.scan.profile }}
{% if result.scan.error %}<br><span class="failed chip">error</span> {{ result.scan.error }}{% endif %}
<br>Records: {{ result.findings|length }}
<br><b>Confirmed vulnerabilities: {{ summary.vulnerabilities_confirmed }}</b>
| potential {{ summary.potential }} | inconclusive {{ summary.inconclusive }} | not-detected {{ summary.not_detected }}
<br><small>hardening items {{ summary.hardening }} | observations {{ summary.observations }} (observations are NOT vulnerabilities)</small></div>
<h2>Findings</h2>
<table class="findings"><thead><tr><th>Severity</th><th>Status</th><th>Kind</th><th>Finding</th><th>Evidence</th><th>Fix</th></tr></thead><tbody>
{% for f in result.findings %}
<tr><td data-h="severity" class="sev-{{f.severity}}">{{f.severity}}</td>
<td data-h="status"><span class="chip {{f.status}}">{{f.status}}</span> <small>conf: {{f.confidence}}</small></td>
<td data-h="kind"><span class="chip kind-{{f.kind or 'vulnerability'}}">{{f.kind or 'vulnerability'}}</span></td>
<td data-h="finding"><b>{{f.title}}</b><br>{{f.description}}{% if f.cwe %}<br><small>{{f.cwe}}</small>{% endif %}</td>
<td data-h="evidence"><pre>{{f.evidence}}</pre></td><td data-h="fix">{{f.remediation}}</td></tr>
{% endfor %}</tbody></table>
<h2>Coverage - tests not run are listed, never implied</h2>
<table class="plain"><thead><tr><th>State</th><th>Check</th><th>Detail</th></tr></thead><tbody>
{% for row in result.coverage %}
<tr><td><span class="chip {{row.state}}">{{row.state}}</span></td><td>{{row.check_id}}</td><td>{{row.detail}}</td></tr>
{% endfor %}</tbody></table>
<p><a href="/report/{{ result.scan.id }}.json">JSON report</a></p>
{% if compare %}
<h2>Retest comparison vs {{ compare.old_scan }}</h2>
<div class="panel">
Fixed: {{ compare.fixed|length }}{% for x in compare.fixed %}<br><small>+ {{x}}</small>{% endfor %}
<br>Still open: {{ compare.still_open|length }}
<br>New: {{ compare.new|length }}{% for x in compare.new %}<br><small>+ {{x}}</small>{% endfor %}
</div>
{% endif %}
{% endif %}
<h2>History</h2>
<table class="plain"><thead><tr><th>Scan</th><th>Target</th><th>Profile</th><th>Status</th></tr></thead><tbody>
{% for s in scans %}<tr><td><a href="/scan/{{s.id}}">{{s.id}}</a></td><td>{{s.target}}</td><td>{{s.profile}}</td><td>{{s.status}}</td></tr>{% endfor %}
</tbody></table>
<h2>External scanner tools (runtime detection)</h2>
<div class="panel">{% for t,path in tools.items() %}{{t}}: {% if path %}{{path}}{% else %}<span class="warn">not installed</span>{% endif %}{% if not loop.last %} | {% endif %}{% endfor %}
<br><small>Missing tools are reported, never faked. Profiles depending on them stay unavailable.</small></div>
</body></html>"""


AUTH_TEMPLATE = """<!doctype html><html><head><meta charset="utf-8"><title>SecureScan - {{mode}}</title>
<style>
body{background:#0b0f14;color:#c9e4ca;font-family:ui-monospace,monospace;margin:0;padding:2rem;max-width:420px;margin:0 auto}
h1{color:#39d353}label{display:block;margin:.6rem 0 .15rem;font-size:.85rem;color:#7ee787}input,button{display:block;width:100%;box-sizing:border-box;background:#0e151c;color:#c9e4ca;border:1px solid #2ea043;border-radius:6px;padding:.6rem;margin:.2rem 0;font-family:inherit}
button{background:#12351c;cursor:pointer}.failed{background:#5c1d3a;color:#ffb3d9;padding:.2rem .6rem;border-radius:4px}
a{color:#58a6ff}</style></head><body>
<h1>SECURESCAN</h1><h2>{{mode}}</h2>
{% if auth_error %}<p class="failed">{{ auth_error }}</p>{% endif %}
<form method="post">
<input type="hidden" name="csrf" value="{{ csrf }}">
<label for="f-username">Username</label>
<input id="f-username" name="username" required autocomplete="username">
<label for="f-password">Password{% if mode == 'Register' %} (minimum 8 characters){% endif %}</label>
<input id="f-password" name="password" type="password" required autocomplete="current-password">
{% if mode == 'Register' %}
<label for="f-org">Organization name (a NEW organization is created; you cannot join an existing one by name)</label>
<input id="f-org" name="org" required>{% endif %}
<button type="submit">{{mode}}</button>
</form>
{% if mode == 'Login' %}<p><a href="/register">Need an account? Register</a></p>
{% else %}<p><a href="/login">Have an account? Login</a></p>{% endif %}
</body></html>"""


JOB_PAGE = """<!doctype html><html><head><meta charset="utf-8">
{% if not done %}<meta http-equiv="refresh" content="2">{% endif %}
<title>Scan job</title><style>
body{background:#0b0f14;color:#c9e4ca;font-family:ui-monospace,monospace;padding:2rem;max-width:700px;margin:0 auto}
h1{color:#39d353}.panel{background:#0e151c;border:1px solid #1d2b23;border-radius:8px;padding:1rem;margin:1rem 0}
button{background:#12351c;color:#c9e4ca;border:1px solid #2ea043;border-radius:6px;padding:.4rem .8rem;font-family:inherit;cursor:pointer}
a{color:#58a6ff}.chip{display:inline-block;padding:.1rem .5rem;border-radius:10px;font-size:.75rem;font-weight:bold}
.running{background:#12351c;color:#7ee787}.queued{background:#3a3a3a;color:#ccc}.complete{background:#12351c;color:#7ee787}
.failed{background:#5c1d3a;color:#ffb3d9}.cancelled{background:#5c4a1d;color:#ffe1a1}
</style></head><body><h1>SCAN JOB</h1>
<div class="panel">
Status: <span class="chip {{job.status}}">{{job.status}}</span><br>
Target: {{job.target}} | Profile {{job.profile}}<br>
{% if job.error %}<br>Error: {{job.error}}{% endif %}
{% if job.status in ['queued','running'] %}
<p>Real job state from the worker - this page refreshes every 2s. No fabricated percentages.</p>
<form method="post" action="/job/{{job.id}}/cancel">
<input type="hidden" name="csrf" value="{{ csrf }}">
<button type="submit">Cancel scan</button></form>
{% elif job.status == 'complete' and job.scan_id %}
<p><a href="/scan/{{job.scan_id}}">Open report</a></p>
{% endif %}
</div><p><a href="/">Back to dashboard</a></p></body></html>"""


def create_app(db_path="securescan.db", secret_key=None):
    app = Flask(__name__)
    # session signing key: env override or random per process (documented:
    # random key means sessions reset on restart - fine for local prototype)
    deploy = os.environ.get("SECURESCAN_DEPLOY", "local")
    secret = secret_key or os.environ.get("SECURESCAN_SECRET")
    if deploy == "shared":
        if not secret:
            raise RuntimeError("SECURESCAN_DEPLOY=shared requires a stable SECURESCAN_SECRET env var")
        app.config.update(SESSION_COOKIE_SECURE=True)  # HTTPS only behind TLS
    app.secret_key = secret or secrets.token_hex(32)
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
    store = Store(db_path)
    from .jobs import JobManager
    jobs = JobManager(store)
    ph = PasswordHasher()
    challenges = ChallengeStore()
    verified_hosts = {}   # (org_id, host) -> expiry timestamp
    login_failures = {}   # username -> [timestamps] (brute-force throttling)
    MAX_FAILS, WINDOW, LOCKOUT = 5, 600, 300
    SCANS_PER_ORG_PER_HOUR = 10
    REGISTRATIONS_PER_HOUR = 20   # per deploy instance (abuse ceiling)

    def csrf_token():
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(16)
        return session["csrf"]

    def csrf_ok():
        return request.form.get("csrf", "") == session.get("csrf", "~none~")

    def throttled(uname):
        fails = [t for t in login_failures.get(uname, [])
                 if time_mod.time() - t < WINDOW]
        login_failures[uname] = fails
        return len(fails) >= MAX_FAILS and (time_mod.time() - fails[-1]) < LOCKOUT

    def current_user():
        uname = session.get("user")
        if not uname:
            return None
        u = store.get_user(uname)
        # server-side invalidation: session must carry the user's CURRENT
        # session_version (bumped on logout)
        if not u or u.get("session_version", 0) != session.get("sv", -1):
            return None
        return u

    def login_required(fn):
        @functools.wraps(fn)
        def wrapper(*a, **kw):
            if not current_user():
                return redirect("/login")
            return fn(*a, **kw)
        return wrapper

    @app.get("/register")
    def register_form():
        return render_template_string(AUTH_TEMPLATE, mode="Register", auth_error=None,
                                      csrf=csrf_token())

    @app.post("/register")
    def register():
        if not csrf_ok():
            abort(400, "bad CSRF token")
        if store.count_recent_orgs(3600) >= REGISTRATIONS_PER_HOUR:
            return render_template_string(AUTH_TEMPLATE, mode="Register",
                                          auth_error="registration temporarily limited - try later",
                                          csrf=csrf_token()), 429
        uname = request.form.get("username", "").strip()
        pw = request.form.get("password", "")
        org = request.form.get("org", "").strip()
        if not uname or not pw or not org:
            return render_template_string(AUTH_TEMPLATE, mode="Register",
                                          auth_error="all fields required",
                                          csrf=csrf_token()), 400
        if len(pw) < 8:
            return render_template_string(AUTH_TEMPLATE, mode="Register",
                                          auth_error="password must be at least 8 characters",
                                          csrf=csrf_token()), 400
        if store.get_user(uname):
            return render_template_string(AUTH_TEMPLATE, mode="Register",
                                          auth_error="username taken",
                                          csrf=csrf_token()), 400
        oid = store.create_org(org)  # ALWAYS a new org id - no join-by-name
        store.create_user(uname, ph.hash(pw), oid)
        session.clear()  # session-fixation defense: fresh session pre-auth
        session["user"] = uname
        session["sv"] = 0
        session["csrf"] = secrets.token_hex(16)
        return redirect("/")

    @app.get("/login")
    def login_form():
        return render_template_string(AUTH_TEMPLATE, mode="Login", auth_error=None,
                                      csrf=csrf_token())

    @app.post("/login")
    def login():
        if not csrf_ok():
            abort(400, "bad CSRF token")
        uname = request.form.get("username", "").strip()
        pw = request.form.get("password", "")
        if throttled(uname):
            return render_template_string(AUTH_TEMPLATE, mode="Login",
                                          auth_error="too many failed attempts - try again in a few minutes",
                                          csrf=csrf_token()), 429
        u = store.get_user(uname)
        ok = False
        if u:
            try:
                ok = ph.verify(u["pw_hash"], pw)
            except VerifyMismatchError:
                ok = False
        if not ok:
            login_failures.setdefault(uname, []).append(time_mod.time())
            return render_template_string(AUTH_TEMPLATE, mode="Login",
                                          auth_error="invalid credentials",
                                          csrf=csrf_token()), 401
        login_failures.pop(uname, None)
        session.clear()  # session-fixation defense
        session["user"] = uname
        session["sv"] = u.get("session_version", 0)
        session["csrf"] = secrets.token_hex(16)
        return redirect("/")

    @app.post("/logout")
    def logout():
        if not csrf_ok():
            abort(400, "bad CSRF token")
        uname = session.get("user")
        if uname:
            store.bump_session_version(uname)  # server-side invalidation
        session.clear()
        return redirect("/login")

    def render(result=None, org_id=None, compare=None):
        summary = {"confirmed": 0, "potential": 0, "inconclusive": 0, "not_detected": 0,
                   "vulnerabilities_confirmed": 0, "hardening": 0, "observations": 0}
        if result:
            for f in result["findings"]:
                key = f["status"].replace("-", "_")
                if key in summary:
                    summary[key] += 1
                kind = f.get("kind") or "vulnerability"
                if kind == "observation":
                    summary["observations"] += 1
                elif kind == "hardening":
                    summary["hardening"] += 1
                elif f["status"] == "confirmed":
                    summary["vulnerabilities_confirmed"] += 1
        return render_template_string(PAGE, result=result, summary=summary,
                                      scans=store.list_scans(org_id=org_id),
                                      profiles=PROFILES,
                                      tools=external_tools_status(),
                                      challenge=None, target=None, profile=None,
                                      verify_error=None, csrf=csrf_token(),
                                      compare=compare)

    @app.get("/")
    @login_required
    def index():
        return render(org_id=current_user()["org_id"])

    import time as _time

    def _render_challenge(challenge, target, profile, verify_error=None, org_id=None):
        summary = {"confirmed": 0, "potential": 0, "inconclusive": 0, "not_detected": 0}
        return render_template_string(PAGE, result=None, summary=summary,
                                      csrf=csrf_token(), compare=None,
                                      scans=store.list_scans(org_id=org_id), profiles=PROFILES,
                                      tools=external_tools_status(),
                                      challenge=challenge, target=target,
                                      profile=profile, verify_error=verify_error)

    @app.post("/scan")
    @login_required
    def scan():
        if not csrf_ok():
            abort(400, "bad CSRF token")
        org_id = current_user()["org_id"]
        target = request.form.get("target", "")
        profile = int(request.form.get("profile", "1"))
        try:
            base = normalize_target(target)
            host = urlparse(base).hostname
            _g = ScopeGuard(base)
            _g.check_url(base)  # DNS + IP screening rejects private/metadata/prohibited targets BEFORE any challenge or network fetch
        except ScopeError as e:
            abort(400, f"target rejected: {e}")
        if verified_hosts.get((org_id, host), 0) < _time.time():
            return _render_challenge(challenges.create(host, org_id), target, profile, org_id=org_id)
        if store.count_recent_scans(org_id, 3600) >= SCANS_PER_ORG_PER_HOUR:
            abort(429, "org scan budget for this hour is exhausted")
        try:
            jid = jobs.submit(target, profile, org_id=org_id)
        except RuntimeError as e:
            abort(429, str(e))
        return redirect(f"/job/{jid}")

    @app.post("/verify-and-scan")
    @login_required
    def verify_and_scan():
        if not csrf_ok():
            abort(400, "bad CSRF token")
        org_id = current_user()["org_id"]
        target = request.form.get("target", "")
        profile = int(request.form.get("profile", "1"))
        try:
            base = normalize_target(target)
            host = urlparse(base).hostname
            guard = ScopeGuard(base)
        except ScopeError as e:
            abort(400, str(e))
        client = SafeClient(guard)
        ok = False
        err = None
        try:
            ok = challenges.verify_web(host, client, org_id)
        except ValueError as e:
            err = str(e)
        if not ok:
            ch = challenges._challenges.get((org_id, host))
            return _render_challenge(ch, target, profile,
                                     verify_error=err or "token not found at the challenge path",
                                     org_id=org_id)
        verified_hosts[(org_id, host)] = _time.time() + 3600
        if store.count_recent_scans(org_id, 3600) >= SCANS_PER_ORG_PER_HOUR:
            abort(429, "org scan budget for this hour is exhausted")
        try:
            jid = jobs.submit(target, profile, org_id=org_id)
        except RuntimeError as e:
            abort(429, str(e))
        return redirect(f"/job/{jid}")

    @app.get("/job/<jid>")
    @login_required
    def job_view(jid):
        j = jobs.get(jid)
        if not j or j.get("org_id") != current_user()["org_id"]:
            abort(404)
        return render_template_string(
            JOB_PAGE, job=j, done=j["status"] not in ("queued", "running"),
            csrf=csrf_token())

    @app.post("/job/<jid>/cancel")
    @login_required
    def job_cancel(jid):
        if not csrf_ok():
            abort(400, "bad CSRF token")
        j = jobs.get(jid)
        if not j or j.get("org_id") != current_user()["org_id"]:
            abort(404)
        jobs.cancel(jid)
        return redirect(f"/job/{jid}")

    if os.environ.get("SECURESCAN_DEMO") == "1" and deploy == "local":
        # LOCAL DEMO SEED ONLY: seeded tenant + synthetic findings so UI states
        # (job progress, retest comparison) can be visually verified. Never
        # enabled in shared deploys; no network targets involved.
        from .findings import Finding as _F
        if not store.get_user("demo"):
            _oid = store.create_org("DemoOrg")
            store.create_user("demo", ph.hash("demo12345"), _oid)
            s1 = store.create_scan("https://demo.example", 2, _oid)
            for f in [_F(check_id="security-headers", title="HTTP security headers",
                         category="http-browser", severity="medium", status="potential",
                         confidence="medium", asset="https://demo.example/", kind="hardening",
                         description="Content-Security-Policy is not set.",
                         remediation="Set a suitable CSP."),
                      _F(check_id="exposed-files", title="Active probe: sensitive file paths",
                         category="attack-surface", severity="high", status="confirmed",
                         confidence="medium", asset="https://demo.example/.git/HEAD",
                         description="Git repository metadata appears publicly accessible.",
                         evidence="GET /.git/HEAD -> 200, pattern matched",
                         remediation="Block .git from the web root.")]:
                store.save_finding(s1, f)
            store.save_coverage(s1, [("security-headers", "completed", "1 record"),
                                     ("active-tests-nuclei-zap", "not-tested", "binaries absent")])
            store.finish_scan(s1, "complete")
            s2 = store.create_scan("https://demo.example", 2, _oid)
            store.save_finding(s2, _F(check_id="security-headers", title="HTTP security headers",
                         category="http-browser", severity="medium", status="potential",
                         confidence="medium", asset="https://demo.example/", kind="hardening",
                         description="Content-Security-Policy is not set.",
                         remediation="Set a suitable CSP."))
            store.save_coverage(s2, [("security-headers", "completed", "1 record")])
            store.finish_scan(s2, "complete")
            import threading as _th, time as _t, uuid as _u
            _jid = "job-" + _u.uuid4().hex[:10]
            jobs.jobs[_jid] = {"id": _jid, "target": "https://demo.example",
                "profile": 2, "org_id": _oid, "status": "running",
                "scan_id": None, "cancel": _th.Event(), "created": _t.time(),
                "error": None}  # static demo job, no worker thread
            store.job_upsert(_jid, _oid, "https://demo.example", 2, "running")

        @app.get("/__demo__/enter/<path:nxt>")
        def demo_enter(nxt):
            session.clear()
            session["user"] = "demo"
            session["sv"] = 0
            session["csrf"] = secrets.token_hex(16)
            return redirect("/" + nxt)

    @app.get("/scan/<sid>")
    @login_required
    def show(sid):
        org_id = current_user()["org_id"]
        result = store.get_scan(sid, org_id=org_id)
        if not result["scan"]:
            abort(404)  # cross-tenant access is indistinguishable from nonexistent
        prev = [s for s in store.latest_for_target(result["scan"]["target"], 3)
                if s["id"] != sid and s["org_id"] == org_id]
        compare = None
        if prev:
            from .report import compare_scans
            compare = compare_scans(store.get_scan(prev[0]["id"], org_id=org_id), result)
        return render(result, org_id=org_id, compare=compare)

    @app.get("/report/<sid>.json")
    @login_required
    def report_json(sid):
        result = store.get_scan(sid, org_id=current_user()["org_id"])
        if not result["scan"]:
            abort(404)
        return build_json(result)
    return app

if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5001, debug=False)
