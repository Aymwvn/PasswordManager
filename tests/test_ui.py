import json
import re

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from passwordmanager.ui.server import AttemptLimiter, create_app, run  # noqa: E402

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
        clipboard=None,
    )


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture
def authed(client):
    res = client.post("/api/init", json={"master_password": MASTER})
    assert res.status_code == 200
    client.headers["X-CSRF-Token"] = res.json()["csrf_token"]  # what the real frontend does
    return client


def test_status_before_and_after_init(client):
    assert client.get("/api/status").json() == {
        "vault_exists": False, "unlocked": False, "seconds_left": None, "csrf_token": None}
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


def test_session_hook_locks_vault(app, authed):
    # The desktop shell uses this to lock when the window is minimized.
    app.state.session.lock()
    assert authed.get("/api/status").json()["unlocked"] is False
    assert authed.get("/api/entries").status_code == 401


# ---- Phase 3 regression tests (one block per finding in docs/SELF_PENTEST.md) ----------------


def _session(client):
    """Init a vault and return its CSRF token, WITHOUT installing it as a default header."""
    return client.post("/api/init", json={"master_password": MASTER}).json()["csrf_token"]


def test_csrf_token_required_on_every_authenticated_write(client):  # F-D
    token = _session(client)
    writes = [
        ("post", "/api/entries", {"json": ENTRY}),
        ("put", "/api/entries/x", {"json": {"url": "u"}}),
        ("delete", "/api/entries/x", {}),
        ("post", "/api/ping", {}),
        ("post", "/api/lock", {}),
    ]
    for method, path, kw in writes:
        call = getattr(client, method)
        assert call(path, **kw).status_code == 403, f"{method} {path} accepted without token"
        assert call(path, headers={"X-CSRF-Token": "wrong"}, **kw).status_code == 403
    ok = client.post("/api/entries", json=ENTRY, headers={"X-CSRF-Token": token})
    assert ok.status_code == 201
    assert client.get("/api/entries").status_code == 200  # reads need no token


def test_csrf_token_only_visible_to_the_session_holder(app, client):
    token = _session(client)
    assert client.get("/api/status").json()["csrf_token"] == token
    assert TestClient(app).get("/api/status").json()["csrf_token"] is None


def test_csrf_token_rotates_on_unlock(client):
    old = _session(client)
    client.post("/api/lock", headers={"X-CSRF-Token": old})
    new = client.post("/api/unlock", json={"master_password": MASTER}).json()["csrf_token"]
    assert new != old
    stale = client.post("/api/entries", json=ENTRY, headers={"X-CSRF-Token": old})
    fresh = client.post("/api/entries", json=ENTRY, headers={"X-CSRF-Token": new})
    assert (stale.status_code, fresh.status_code) == (403, 201)


def test_failed_csrf_does_not_count_as_activity(client, clock):
    _session(client)
    clock.now += 50
    assert client.post("/api/ping", headers={"X-CSRF-Token": "wrong"}).status_code == 403
    clock.now += 20  # 70s since the last *valid* activity > 60s ttl
    assert client.get("/api/entries").status_code == 401


@pytest.mark.parametrize("site", ["cross-site", "same-site"])
def test_sec_fetch_site_blocks_non_same_origin_writes(authed, site):  # F-D, defence in depth
    blocked = authed.post("/api/entries", json=ENTRY, headers={"Sec-Fetch-Site": site})
    assert blocked.status_code == 403
    ok = authed.post("/api/entries", json=ENTRY, headers={"Sec-Fetch-Site": "same-origin"})
    assert ok.status_code == 201


def test_non_json_content_type_is_not_parsed_as_json(authed):
    res = authed.post(
        "/api/entries", content=json.dumps(ENTRY), headers={"Content-Type": "text/plain"}
    )
    assert res.status_code == 422


def test_unlock_lockout_escalates_and_resets(client, clock):  # F-C
    token = _session(client)
    client.post("/api/lock", headers={"X-CSRF-Token": token})
    bad = {"master_password": "wrong wrong wrong"}
    assert [client.post("/api/unlock", json=bad).status_code for _ in range(3)] == [401, 401, 401]
    res = client.post("/api/unlock", json=bad)
    assert res.status_code == 429 and res.headers["retry-after"] == "5"
    # Even the correct password is refused during lockout (and no Argon2 work is done).
    assert client.post("/api/unlock", json={"master_password": MASTER}).status_code == 429
    clock.now += 6
    assert client.post("/api/unlock", json=bad).status_code == 401  # failure #4 -> 10 s
    res = client.post("/api/unlock", json=bad)
    assert res.status_code == 429 and res.headers["retry-after"] == "10"
    clock.now += 11
    good = client.post("/api/unlock", json={"master_password": MASTER})
    assert good.status_code == 200
    # A success resets the counter: three fresh free attempts again.
    client.post("/api/lock", headers={"X-CSRF-Token": good.json()["csrf_token"]})
    assert [client.post("/api/unlock", json=bad).status_code for _ in range(3)] == [401, 401, 401]


def test_lockout_is_capped_at_fifteen_minutes():
    clock = FakeClock()
    limiter = AttemptLimiter(clock)
    for _ in range(40):
        limiter.record_failure()
    assert limiter.blocked_for() == 900
    clock.now += 901
    assert limiter.blocked_for() == 0


def test_oversized_body_rejected_before_parsing(client):  # F-C
    big = b'{"master_password":"' + b"A" * 200_000 + b'"}'
    res = client.post("/api/init", content=big, headers={"Content-Type": "application/json"})
    assert res.status_code == 413
    assert "content-security-policy" in res.headers


def test_oversized_chunked_body_rejected(client):  # no Content-Length to pre-check
    def chunks():
        for _ in range(300):
            yield b"A" * 1000

    res = client.post("/api/init", content=chunks(), headers={"Content-Type": "application/json"})
    assert res.status_code == 413
    assert client.get("/api/status").status_code == 200  # server still healthy


def test_maximum_legitimate_entry_still_fits_under_the_cap(authed):
    entry = {"name": "n" * 200, "username": "u" * 500, "password": "p" * 1024,
             "url": "h" * 2000, "notes": "\u00e9" * 10_000}
    assert authed.post("/api/entries", json=entry).status_code == 201


# ---- Phase 4: TOTP endpoint and opt-in breach check -------------------------------------------

import threading  # noqa: E402

from passwordmanager.core import breach  # noqa: E402

RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


def test_totp_endpoint_returns_a_live_code(authed):
    res = authed.post("/api/entries", json={**ENTRY, "totp": RFC_SECRET})
    assert res.status_code == 201 and res.json()["has_totp"] is True
    body = authed.get("/api/totp/github").json()
    assert re.fullmatch(r"\d{6}", body["code"])
    assert 1 <= body["seconds_remaining"] <= 30 and body["period"] == 30
    assert authed.get("/api/entries/github").json()["totp"] == RFC_SECRET


def test_totp_secret_never_appears_in_the_list_view(authed):
    authed.post("/api/entries", json={**ENTRY, "totp": RFC_SECRET})
    listing = authed.get("/api/entries").json()[0]
    assert "totp" not in listing and listing["has_totp"] is True


def test_totp_requires_a_session(client):
    assert client.get("/api/totp/github").status_code == 401


def test_totp_error_cases(authed):
    authed.post("/api/entries", json=ENTRY)
    assert authed.get("/api/totp/github").status_code == 404  # no secret configured
    assert authed.get("/api/totp/missing").status_code == 404
    bad = authed.post("/api/entries", json={**ENTRY, "name": "bad", "totp": "not base32!!"})
    assert bad.status_code == 422
    assert [e["name"] for e in authed.get("/api/entries").json()] == ["github"]


def test_totp_can_be_cleared_through_update(authed):
    authed.post("/api/entries", json={**ENTRY, "totp": RFC_SECRET})
    assert authed.put("/api/entries/github", json={"totp": ""}).json()["has_totp"] is False
    assert authed.get("/api/totp/github").status_code == 404


@pytest.fixture
def breach_calls():
    return []


@pytest.fixture
def breach_client(tmp_path, fast_params, clock, breach_calls):
    def fetch(prefix):
        breach_calls.append(prefix)
        _, suffix = breach.sha1_parts("hunter2hunter2")
        return f"{suffix}:42\r\nAAAAAAAAAAAAAAAA:1"

    app = create_app(tmp_path / "v.bin", allowed_hosts={"testserver"}, kdf_params=fast_params,
                     clock=clock, breach_fetcher=fetch)
    client = TestClient(app)
    token = client.post("/api/init", json={"master_password": MASTER}).json()["csrf_token"]
    client.headers["X-CSRF-Token"] = token
    return client


def test_breach_check_sends_only_a_five_character_prefix(breach_client, breach_calls):
    breach_client.post("/api/entries", json={"name": "a", "password": "hunter2hunter2"})
    assert breach_client.post("/api/breach/a").json() == {"breached": True, "count": 42}
    breach_client.post("/api/entries", json={"name": "b", "password": "a-different-one-77"})
    assert breach_client.post("/api/breach/b").json() == {"breached": False, "count": 0}
    assert len(breach_calls) == 2 and all(len(p) == 5 for p in breach_calls)


def test_breach_check_needs_a_session_and_a_csrf_token(breach_client, breach_calls, app):
    breach_client.post("/api/entries", json={"name": "a", "password": "hunter2hunter2"})
    token = breach_client.headers.pop("X-CSRF-Token")
    assert breach_client.post("/api/breach/a").status_code == 403  # a web page can't trigger it
    assert breach_calls == []
    assert TestClient(app).post("/api/breach/a").status_code == 401
    breach_client.headers["X-CSRF-Token"] = token


def test_breach_check_errors(tmp_path, fast_params):
    def offline(_prefix):
        raise breach.BreachCheckError("could not reach the breach-check service")

    app = create_app(tmp_path / "v.bin", allowed_hosts={"testserver"}, kdf_params=fast_params,
                     breach_fetcher=offline)
    client = TestClient(app)
    client.headers["X-CSRF-Token"] = client.post(
        "/api/init", json={"master_password": MASTER}).json()["csrf_token"]
    client.post("/api/entries", json={"name": "a", "password": "pw"})
    client.post("/api/entries", json={"name": "empty"})
    res = client.post("/api/breach/a")
    assert res.status_code == 502 and "could not reach" in res.json()["detail"]
    assert client.post("/api/breach/empty").status_code == 422
    assert client.post("/api/breach/missing").status_code == 404


def test_vault_stays_responsive_while_a_breach_lookup_is_in_flight(
    tmp_path, fast_params
):
    started, release = threading.Event(), threading.Event()

    def slow_fetch(_prefix):
        started.set()
        release.wait(5)
        return ""

    app = create_app(tmp_path / "v.bin", allowed_hosts={"testserver"}, kdf_params=fast_params,
                     breach_fetcher=slow_fetch)
    main = TestClient(app)
    token = main.post("/api/init", json={"master_password": MASTER}).json()["csrf_token"]
    main.headers["X-CSRF-Token"] = token
    main.post("/api/entries", json={"name": "a", "password": "pw"})
    other = TestClient(app, headers={"X-CSRF-Token": token})
    other.cookies.update(main.cookies)
    worker = threading.Thread(target=lambda: other.post("/api/breach/a"))
    worker.start()
    try:
        assert started.wait(5)
        assert main.get("/api/entries").status_code == 200  # mutex is not held during the request
    finally:
        release.set()
        worker.join(5)


@pytest.mark.parametrize("name", ["a\nb", "\n"])
def test_api_rejects_names_that_could_not_be_addressed_later(authed, name):  # F-E
    assert authed.post("/api/entries", json={**ENTRY, "name": name}).status_code == 422
    assert authed.get("/api/entries").json() == []


# ---- Phase 4b: native clipboard endpoints -------------------------------------------------------

from .conftest import FakeClipboard  # noqa: E402


@pytest.fixture
def clip(tmp_path, fast_params, clock):
    fake = FakeClipboard()
    app = create_app(tmp_path / "v.bin", allowed_hosts={"testserver"}, auto_lock_seconds=60,
                     kdf_params=fast_params, clock=clock, clipboard=fake)
    client = TestClient(app)
    token = client.post("/api/init", json={"master_password": MASTER}).json()["csrf_token"]
    client.headers["X-CSRF-Token"] = token
    client.post("/api/entries", json={**ENTRY, "totp": RFC_SECRET})
    return client, fake, app


def test_capabilities_reflect_whether_a_native_clipboard_exists(tmp_path, fast_params):
    without = create_app(tmp_path / "a.bin", allowed_hosts={"testserver"}, kdf_params=fast_params,
                         clipboard=None)
    with_one = create_app(tmp_path / "b.bin", allowed_hosts={"testserver"}, kdf_params=fast_params,
                          clipboard=FakeClipboard())
    assert TestClient(without).get("/api/capabilities").json() == {"native_clipboard": False}
    assert TestClient(with_one).get("/api/capabilities").json() == {"native_clipboard": True}


def test_copy_puts_password_and_code_on_the_native_clipboard(clip):
    client, fake, _ = clip
    res = client.post("/api/copy", json={"name": "github", "field": "password"})
    assert res.json() == {"copied": True, "clears_in": 15}
    assert fake.text == ENTRY["password"]
    client.post("/api/copy", json={"name": "github", "field": "totp"})
    assert re.fullmatch(r"\d{6}", fake.text)


def test_copy_needs_a_session_and_a_csrf_token(clip, app):
    client, fake, live_app = clip
    token = client.headers.pop("X-CSRF-Token")
    body = {"name": "github", "field": "password"}
    assert client.post("/api/copy", json=body).status_code == 403
    assert TestClient(live_app).post("/api/copy", json=body).status_code == 401
    assert fake.copied == []
    client.headers["X-CSRF-Token"] = token


@pytest.mark.parametrize(
    "body,status",
    [
        ({"name": "github", "field": "username"}, 422),  # only secrets use the native path
        ({"name": "github", "field": "notes"}, 422),
        ({"name": "", "field": "password"}, 422),
        ({"name": "missing", "field": "password"}, 404),
    ],
)
def test_copy_rejects_bad_requests(clip, body, status):
    client, fake, _ = clip
    assert client.post("/api/copy", json=body).status_code == status
    assert fake.copied == []


def test_copy_of_empty_or_unconfigured_fields(clip):
    client, fake, _ = clip
    client.post("/api/entries", json={"name": "bare"})
    assert client.post("/api/copy", json={"name": "bare", "field": "password"}).status_code == 422
    assert client.post("/api/copy", json={"name": "bare", "field": "totp"}).status_code == 404
    assert fake.copied == []


def test_copy_without_a_native_clipboard_is_501(authed):
    # `app` is built with clipboard=None, so the frontend must fall back to the browser
    authed.post("/api/entries", json=ENTRY)
    res = authed.post("/api/copy", json={"name": "github", "field": "password"})
    assert res.status_code == 501


def test_locking_wipes_a_copied_secret_from_the_clipboard(clip):
    client, fake, _ = clip
    client.post("/api/copy", json={"name": "github", "field": "password"})
    client.post("/api/lock")
    assert fake.text == ""


def test_locking_never_wipes_something_else_the_user_copied(clip):
    client, fake, _ = clip
    client.post("/api/copy", json={"name": "github", "field": "password"})
    fake.user_copies("my shopping list")
    client.post("/api/lock")
    assert fake.text == "my shopping list"


def test_idle_auto_lock_also_wipes_the_clipboard(clip, clock):
    client, fake, _ = clip
    client.post("/api/copy", json={"name": "github", "field": "password"})
    clock.now += 61
    assert client.get("/api/status").json()["unlocked"] is False
    assert fake.text == ""


def test_frontend_prefers_the_native_clipboard_for_secrets(client):
    js = client.get("/app.js").text
    assert '"/capabilities"' in js and '"/copy"' in js and "copySecret(" in js
