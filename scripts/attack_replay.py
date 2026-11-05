"""Replay concrete attacks against a live local server and print a markdown results table.

Usage:  python scripts/attack_replay.py   (needs: pip install -e ".[dev]")
The table in docs/SELF_PENTEST.md was produced by this script.
"""

import http.client, tempfile, time
from pathlib import Path
from urllib.parse import quote
import httpx
from passwordmanager.app import start_server

MASTER = "correct horse battery staple"
rows = []
def row(name, expected, observed, ok):
    rows.append((name, expected, observed, "PASS" if ok else "FAIL"))

with tempfile.TemporaryDirectory() as tmp:
    srv = start_server(Path(tmp) / "vault.bin")
    base = f"http://127.0.0.1:{srv.port}"
    try:
        c = httpx.Client(base_url=base)
        r = c.post("/api/init", json={"master_password": MASTER})
        tok = r.json()["csrf_token"]; H = {"X-CSRF-Token": tok}
        cookie_hdr = r.headers["set-cookie"].lower()

        r = c.get("/api/status", headers={"Host": "evil.example"})
        row("DNS rebinding: spoofed `Host: evil.example`", "400", r.status_code, r.status_code == 400)

        r = c.post("/api/entries", json={"name": "a"}, headers={**H, "Origin": "http://evil.example"})
        row("CSRF: write with foreign `Origin` (valid cookie + token)", "403", r.status_code, r.status_code == 403)

        r = c.post("/api/entries", json={"name": "a"}, headers={**H, "Sec-Fetch-Site": "cross-site"})
        row("CSRF: write with `Sec-Fetch-Site: cross-site`", "403", r.status_code, r.status_code == 403)

        r = c.post("/api/entries", json={"name": "a"})
        row("CSRF: write with valid cookie, **no** token, no Origin", "403", r.status_code, r.status_code == 403)

        r = c.post("/api/entries", json={"name": "a"}, headers={"X-CSRF-Token": "A" * 43})
        row("CSRF: write with forged token", "403", r.status_code, r.status_code == 403)

        r = httpx.get(base + "/api/entries")
        row("Auth: read entries without a session cookie", "401", r.status_code, r.status_code == 401)

        r = c.post("/api/entries", json={"name": "<img src=x onerror=alert(1)>", "password": "p"}, headers=H)
        created = r.status_code
        g = c.get("/api/entries/" + quote("<img src=x onerror=alert(1)>", safe=""))
        ct, nosniff = g.headers["content-type"], g.headers.get("x-content-type-options")
        row("XSS: store `<img onerror>` as entry name; API never serves it as HTML",
            "201, application/json, nosniff", f"{created}, {ct}, {nosniff}",
            created == 201 and ct.startswith("application/json") and nosniff == "nosniff")

        r = c.get("/docs"); r2 = c.get("/openapi.json")
        row("Recon: `/docs` and `/openapi.json`", "404, 404", f"{r.status_code}, {r2.status_code}",
            r.status_code == r2.status_code == 404)

        res = []
        for path in ("/../../pyproject.toml", "/%2e%2e/%2e%2e/pyproject.toml", "/..%2f..%2fpyproject.toml",
                     "/static/../../../etc/passwd"):
            conn = http.client.HTTPConnection("127.0.0.1", srv.port)
            conn.request("GET", path, headers={"Host": f"127.0.0.1:{srv.port}"})
            resp = conn.getresponse(); body = resp.read().decode("utf-8", "replace"); conn.close()
            res.append((resp.status, "[project]" in body or "root:" in body))
        row("Path traversal on static files (4 variants, raw requests)", "no file contents leaked",
            ", ".join(str(s) for s, _ in res), not any(leak for _, leak in res))

        r = c.options("/api/entries", headers={"Origin": "http://evil.example", "Access-Control-Request-Method": "POST"})
        row("CORS: preflight from `evil.example` gets no allow-origin header", "no ACAO header",
            f"{r.status_code}, ACAO={r.headers.get('access-control-allow-origin')}",
            "access-control-allow-origin" not in r.headers)

        r = c.get("/")
        row("Clickjacking: framing is forbidden", "X-Frame-Options DENY + frame-ancestors 'none'",
            f"{r.headers.get('x-frame-options')}, frame-ancestors present={'frame-ancestors' in r.headers['content-security-policy']}",
            r.headers.get("x-frame-options") == "DENY" and "frame-ancestors 'none'" in r.headers["content-security-policy"])

        r = c.post("/api/init", content=b'{"master_password":"' + b"A" * 200_000 + b'"}', headers={"Content-Type": "application/json"})
        def chunks():
            for _ in range(300): yield b"A" * 1000
        r2 = c.post("/api/init", content=chunks(), headers={"Content-Type": "application/json"})
        row("DoS: 200 KB body, and 300 KB chunked body", "413, 413", f"{r.status_code}, {r2.status_code}",
            r.status_code == r2.status_code == 413)

        r = c.post("/api/entries", content='{"name":"x"}', headers={**H, "Content-Type": "text/plain"})
        row("CSRF: `text/plain` body (simple-request trick)", "422", r.status_code, r.status_code == 422)

        row("Cookie flags", "HttpOnly + SameSite=Strict", "httponly" in cookie_hdr and "samesite=strict" in cookie_hdr and "HttpOnly, SameSite=Strict",
            "httponly" in cookie_hdr and "samesite=strict" in cookie_hdr)

        # session replay after lock + re-unlock
        old_cookie = c.cookies["pm_session"]
        c.post("/api/lock", headers=H)
        r = c.post("/api/unlock", json={"master_password": MASTER}); new_tok = r.json()["csrf_token"]
        replay = httpx.get(base + "/api/entries", cookies={"pm_session": old_cookie})
        replay_w = c.post("/api/entries", json={"name": "b"}, headers=H)  # old CSRF token
        row("Session replay: old cookie / old CSRF token after lock + re-unlock", "401 / 403",
            f"{replay.status_code} / {replay_w.status_code}", replay.status_code == 401 and replay_w.status_code == 403)

        # brute force last (it locks the unlock endpoint out)
        c.post("/api/lock", headers={"X-CSRF-Token": new_tok})
        seq, retry, t0 = [], None, time.monotonic()
        for i in range(10):
            r = c.post("/api/unlock", json={"master_password": f"guess-{i}-xxxxxxxx"})
            seq.append(r.status_code)
            if r.status_code == 429 and retry is None: retry = r.headers.get("retry-after")
        elapsed = time.monotonic() - t0
        r = c.post("/api/unlock", json={"master_password": MASTER})
        row("Brute force: 10 wrong guesses, then the *correct* password during lockout",
            "401,401,401 then 429...; correct pw also 429",
            f"{','.join(map(str, seq))} (Retry-After {retry}s, {elapsed:.1f}s total); correct pw -> {r.status_code}",
            seq[:3] == [401, 401, 401] and all(s == 429 for s in seq[3:]) and r.status_code == 429)
    finally:
        srv.stop()

print("| # | Attack | Expected | Observed | Result |\n|---|---|---|---|---|")
for i, (n, e, o, res) in enumerate(rows, 1):
    print(f"| {i} | {n} | {e} | {o} | **{res}** |")
print(f"\n{sum(r[3]=='PASS' for r in rows)}/{len(rows)} passed")
