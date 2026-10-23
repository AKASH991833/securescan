"""Dark-console web UI (English). Local prototype: synchronous scans against
targets the operator is authorized to test. allow_private is NOT set here, so
user-entered targets can never hit localhost/private addresses."""
from urllib.parse import urlparse
from flask import Flask, request, render_template_string, abort
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
<span class="demo">LOCAL PROTOTYPE - profile 1 (passive) + profile 2 subset (crawl, path probes, testssl) implemented; profiles 3-5 unavailable</span>
<div class="panel">
<form method="post" action="/scan" class="scanform">
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
{% endif %}
<h2>History</h2>
<table class="plain"><thead><tr><th>Scan</th><th>Target</th><th>Profile</th><th>Status</th></tr></thead><tbody>
{% for s in scans %}<tr><td><a href="/scan/{{s.id}}">{{s.id}}</a></td><td>{{s.target}}</td><td>{{s.profile}}</td><td>{{s.status}}</td></tr>{% endfor %}
</tbody></table>
<h2>External scanner tools (runtime detection)</h2>
<div class="panel">{% for t,path in tools.items() %}{{t}}: {% if path %}{{path}}{% else %}<span class="warn">not installed</span>{% endif %}{% if not loop.last %} | {% endif %}{% endfor %}
<br><small>Missing tools are reported, never faked. Profiles depending on them stay unavailable.</small></div>
</body></html>"""

def create_app(db_path="securescan.db"):
    app = Flask(__name__)
    store = Store(db_path)
    challenges = ChallengeStore()
    verified_hosts = {}  # host -> expiry timestamp

    def render(result=None):
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
                                      scans=store.list_scans(), profiles=PROFILES,
                                      tools=external_tools_status(),
                                      challenge=None, target=None, profile=None,
                                      verify_error=None)

    @app.get("/")
    def index():
        return render()

    import time as _time

    def _render_challenge(challenge, target, profile, verify_error=None):
        summary = {"confirmed": 0, "potential": 0, "inconclusive": 0, "not_detected": 0}
        return render_template_string(PAGE, result=None, summary=summary,
                                      scans=store.list_scans(), profiles=PROFILES,
                                      tools=external_tools_status(),
                                      challenge=challenge, target=target,
                                      profile=profile, verify_error=verify_error)

    @app.post("/scan")
    def scan():
        target = request.form.get("target", "")
        profile = int(request.form.get("profile", "1"))
        try:
            base = normalize_target(target)
            host = urlparse(base).hostname
            _g = ScopeGuard(base)
            _g.check_url(base)  # DNS + IP screening rejects private/metadata/prohibited targets BEFORE any challenge or network fetch
        except ScopeError as e:
            abort(400, f"target rejected: {e}")
        if verified_hosts.get(host, 0) < _time.time():
            return _render_challenge(challenges.create(host), target, profile)
        try:
            result = run_scan(target, profile, store)  # allow_private defaults False
        except ValueError as e:
            abort(400, str(e))
        return render(result)

    @app.post("/verify-and-scan")
    def verify_and_scan():
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
            ok = challenges.verify_web(host, client)
        except ValueError as e:
            err = str(e)
        if not ok:
            ch = challenges._challenges.get(host)
            return _render_challenge(ch, target, profile,
                                     verify_error=err or "token not found at the challenge path")
        verified_hosts[host] = _time.time() + 3600
        result = run_scan(target, profile, store)
        return render(result)

    @app.get("/scan/<sid>")
    def show(sid):
        return render(store.get_scan(sid))

    @app.get("/report/<sid>.json")
    def report_json(sid):
        return build_json(store.get_scan(sid))
    return app

if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5001, debug=False)
