import re

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from passwordmanager.ui.server import create_app, run  # noqa: E402

MASTER = "correct horse battery"
ENTRY = {"name": "github", "username": "aymen", "password": "s3cret-pass", "url": "https://github.com"}


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def app(tmp_path, fast_params, clock):
    return create_app(
        tmp_path / "v.bin",
        allowed_hosts={"testserver"},
        auto_lock_seconds=60,
        kdf_params=fast_params,
        clock=clock,
    )


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture
def authed(client):
    assert client.post("/api/init", json={"master_password": MASTER}).status_code == 200
    return client


def test_status_before_and_after_init(client):
    assert client.get("/api/status").json() == {
        "vault_exists": False, "unlocked": False, "seconds_left": None}
    client.post("/api/init", json={"master_password": MASTER})
    st = client.get("/api/status").json()
    assert st["vault_exists"] and st["unlocked"] and st["seconds_left"] == 60


def test_weak_master_rejected_on_init(client):
    assert client.post("/api/init", json={"master_password": "short"}).status_code == 422


def test_init_twice_conflicts(authed):
    assert authed.post("/api/init", json={"master_password": MASTER}).status_code == 409


def test_entries_require_session(client):
    for method, path in [("get", "/api/entries"), ("get", "/api/entries/x"),
                         ("post", "/api/lock"), ("post", "/api/ping")]:
        assert getattr(client, method)(path).status_code == 401


def test_crud_flow_and_list_hides_passwords(authed):
    assert authed.post("/api/entries", json=ENTRY).status_code == 201
    listing = authed.get("/api/entries").json()
    assert listing[0]["name"] == "github" and "password" not in listing[0]
    assert authed.get("/api/entries/github").json()["password"] == "s3cret-pass"
    assert authed.put("/api/entries/github", json={"password": "new-pass-1"}).status_code == 200
    assert authed.get("/api/entries/github").json()["password"] == "new-pass-1"
    assert authed.get("/api/entries", params={"q": "GIT"}).json()[0]["name"] == "github"
    assert authed.get("/api/entries", params={"q": "nomatch"}).json() == []
    assert authed.delete("/api/entries/github").status_code == 200
    assert authed.get("/api/entries/github").status_code == 404


def test_error_statuses(authed):
    authed.post("/api/entries", json=ENTRY)
    assert authed.post("/api/entries", json=ENTRY).status_code == 409
    assert authed.put("/api/entries/github", json={}).status_code == 422
    assert authed.put("/api/entries/missing", json={"url": "x"}).status_code == 404
    assert authed.post("/api/entries", json={"name": ""}).status_code == 422


def test_names_with_slashes(authed):
    authed.post("/api/entries", json={**ENTRY, "name": "work/vpn"})
    assert authed.get("/api/entries/work%2Fvpn").json()["name"] == "work/vpn"


def test_wrong_master_then_lock_unlock(authed):
    authed.post("/api/lock")
    assert authed.get("/api/entries").status_code == 401
    bad = authed.post("/api/unlock", json={"master_password": "wrong wrong wrong"})
    assert bad.status_code == 401
    assert authed.post("/api/unlock", json={"master_password": MASTER}).status_code == 200
    assert authed.get("/api/entries").status_code == 200


def test_session_token_rotates_and_old_one_is_dead(app, authed):
    old = authed.cookies.get("pm_session")
    authed.post("/api/lock")
    authed.post("/api/unlock", json={"master_password": MASTER})
    assert authed.cookies.get("pm_session") != old
    replay = TestClient(app, headers={"cookie": f"pm_session={old}"})
    assert replay.get("/api/entries").status_code == 401


def test_cookie_flags(client):
    res = client.post("/api/init", json={"master_password": MASTER})
    cookie = res.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie


def test_idle_auto_lock_and_ping(authed, clock):
    clock.now += 50
    assert authed.post("/api/ping").status_code == 200  # activity resets the timer
    clock.now += 50
    assert authed.get("/api/entries").status_code == 200
    clock.now += 61
    assert authed.get("/api/status").json()["unlocked"] is False
    assert authed.get("/api/entries").status_code == 401


def test_status_polling_does_not_extend_session(authed, clock):
    for _ in range(5):
        clock.now += 20
        authed.get("/api/status")
    assert authed.get("/api/entries").status_code == 401  # 100s idle > 60s ttl


def test_host_header_allowlist(client):
    assert client.get("/api/status", headers={"host": "evil.example"}).status_code == 400
    assert client.get("/", headers={"host": "evil.example"}).status_code == 400


def test_cross_origin_writes_blocked(authed):
    bad = authed.post("/api/entries", json=ENTRY, headers={"origin": "http://evil.example"})
    assert bad.status_code == 403
    ok = authed.post("/api/entries", json=ENTRY, headers={"origin": "http://testserver"})
    assert ok.status_code == 201


def test_security_headers(client):
    for path in ("/api/status", "/"):
        h = client.get(path).headers
        assert "default-src 'none'" in h["content-security-policy"]
        assert "script-src 'self'" in h["content-security-policy"]
        assert h["cache-control"] == "no-store"
        assert h["x-frame-options"] == "DENY"
        assert h["x-content-type-options"] == "nosniff"


def test_no_api_docs_exposed(client):
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


def test_frontend_is_csp_friendly(client):
    html = client.get("/").text
    assert "PasswordManager" in html
    assert not re.search(r"<script(?![^>]*\bsrc=)", html), "inline <script> would break the CSP"
    assert " style=" not in html and "<style" not in html
    assert not re.search(r"\son\w+=", html), "inline event handlers would break the CSP"
    assert client.get("/app.js").status_code == 200
    assert client.get("/style.css").status_code == 200


def test_frontend_never_uses_innerhtml(client):
    js = client.get("/app.js").text
    for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
        assert banned not in js


def test_generate_endpoint(client):
    ok = client.get("/api/generate", params={"length": 24}).json()
    assert len(ok["password"]) == 24 and ok["label"] == "strong"
    assert client.get("/api/generate", params={"length": 4}).status_code == 422
    assert client.get("/api/generate", params={"length": 500}).status_code == 422
    assert client.get("/api/generate", params={"symbols": "false"}).json()["password"].isalnum()


def test_run_refuses_non_loopback(tmp_path):
    with pytest.raises(ValueError):
        run(tmp_path / "v.bin", host="192.168.1.5")
