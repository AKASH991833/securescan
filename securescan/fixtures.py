"""Local intentionally-misconfigured fixture app for testing detection.
Runs on 127.0.0.1 only. Two modes: 'vuln' and 'hardened'."""
from flask import Flask, Response

VULN_HTML = """<html><head>
<meta name="generator" content="FixtureCMS 1.0">
<script src="http://127.0.0.1:5999/insecure.js"></script>
</head><body>
<h1>Fixture site</h1>
<a href="/page2">page two</a>
<form method="post" action="/contact"><input name="msg"><button>Send</button></form>
<form method="post" action="http://127.0.0.1:5999/login">
<input name="u"><input type="password" name="p"><button>Login</button></form>
</body></html>"""

HARDENED_HTML = """<html><head><title>Hardened fixture</title></head>
<body><h1>OK</h1>
<form method="post" action="/contact"><input type="hidden" name="csrf_token" value="abc">
<input name="msg"></form></body></html>"""

def make_fixture(mode="vuln"):
    app = Flask("fixture-" + mode)

    @app.get("/")
    def index():
        html = VULN_HTML if mode == "vuln" else HARDENED_HTML
        resp = Response(html, 200, {"Content-Type": "text/html"})
        if mode == "vuln":
            resp.headers["Server"] = "nginx/1.18.0"
            resp.headers["Set-Cookie"] = "session=fixturevalue123; Path=/"
            resp.headers["Access-Control-Allow-Origin"] = "*"
            resp.headers["Access-Control-Allow-Credentials"] = "true"
        else:
            resp.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
            resp.headers["Strict-Transport-Security"] = "max-age=63072000"
            resp.headers["X-Content-Type-Options"] = "nosniff"
            resp.headers["Referrer-Policy"] = "no-referrer"
            resp.headers["Set-Cookie"] = "session=x; Path=/; Secure; HttpOnly; SameSite=Lax"
        return resp

    @app.get("/reflect")
    def reflect():
        from flask import request as _req
        resp = Response("ok", 200)
        if mode == "vuln":
            resp.headers["Access-Control-Allow-Origin"] = _req.headers.get("Origin", "")
            resp.headers["Access-Control-Allow-Credentials"] = "true"
        return resp

    @app.get("/redirect-meta")
    def redirect_meta():
        from flask import redirect as _redir
        return _redir("http://169.254.169.254/latest/meta-data")

    @app.get("/page2")
    def page2():
        if mode == "vuln":
            return Response("""<html><body><h1>Page 2</h1>
<form method="post" action="/update"><input name="email"></form>
<script src="http://127.0.0.1:5999/x.js"></script>
</body></html>""", 200, {"Content-Type": "text/html"})
        return Response("<html><body>ok</body></html>", 200,
                        {"Content-Type": "text/html"})

    @app.get("/.env")
    def env_file():
        if mode == "vuln":
            return Response("DB_PASSWORD=fake-fixture-value\nAPI_KEY=fake123\n", 200)
        return Response("not found", 404)

    @app.get("/.git/HEAD")
    def git_head():
        if mode == "vuln":
            return Response("ref: refs/heads/main\n", 200)
        return Response("not found", 404)

    @app.get("/robots.txt")
    def robots():
        return Response("User-agent: *\nDisallow: /admin\n", 200)

    @app.get("/.well-known/securescan-verification.txt")
    def challenge():
        import os
        return Response(os.environ.get("FIXTURE_CHALLENGE", "unset"), 200,
                        {"Content-Type": "text/plain"})
    return app
