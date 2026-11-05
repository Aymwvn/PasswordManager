"""Local web UI backend (FastAPI). Single user, single vault, loopback only.

Defences (see docs/THREAT_MODEL.md and docs/SELF_PENTEST.md):
  * Host header allow-list              -> blocks DNS rebinding
  * Origin + Sec-Fetch-Site on writes   -> blocks cross-site requests from browsers
  * Per-session CSRF token (header)     -> required on every authenticated write, even w/o Origin
  * Random per-unlock session token     -> HttpOnly + SameSite=Strict cookie, rotated on unlock
  * Unlock throttling                   -> exponential lockout after repeated failures (429)
  * Request body cap                    -> 413 before big bodies are buffered/parsed
  * Idle auto-lock                      -> watchdog task + lazy check per request
  * Strict CSP, no-store caching, API docs disabled
"""

from __future__ import annotations

import asyncio
import math
import secrets
import threading
import time
import webbrowser
from collections.abc import Callable
from contextlib import asynccontextmanager
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urlparse

import uvicorn
from fastapi import Cookie, Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from passwordmanager.core.crypto import KdfParams
from passwordmanager.core.generator import estimate_entropy_bits, generate_password, strength_label
from passwordmanager.core.vault import (
    Entry,
    EntryExists,
    EntryNotFound,
    InvalidPassword,
    Vault,
    VaultCorrupted,
    VaultError,
    VaultExists,
    VaultLocked,
    VaultNotFound,
    WeakMasterPassword,
)

STATIC_DIR = Path(__file__).parent / "static"
COOKIE_NAME = "pm_session"
CSRF_HEADER = "x-csrf-token"
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
MAX_BODY_BYTES = 128 * 1024  # largest legitimate request is well under 100 KB

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}

_ERROR_STATUS: dict[type[Exception], int] = {
    EntryNotFound: 404,
    VaultNotFound: 404,
    EntryExists: 409,
    VaultExists: 409,
    InvalidPassword: 401,
    VaultLocked: 401,
    WeakMasterPassword: 422,
    VaultCorrupted: 500,
}


# ---- request models ------------------------------------------------------------------------


class MasterIn(BaseModel):
    master_password: str = Field(min_length=1, max_length=1024)


class EntryIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    username: str = Field("", max_length=500)
    password: str = Field("", max_length=1024)
    url: str = Field("", max_length=2000)
    notes: str = Field("", max_length=10_000)


class EntryUpdate(BaseModel):
    username: str | None = Field(None, max_length=500)
    password: str | None = Field(None, max_length=1024)
    url: str | None = Field(None, max_length=2000)
    notes: str | None = Field(None, max_length=10_000)


def _summary(entry: Entry) -> dict:
    """List view: never includes the password."""
    return {
        "name": entry.name,
        "username": entry.username,
        "url": entry.url,
        "updated": entry.updated,
    }


# ---- unlock throttling ---------------------------------------------------------------------


class AttemptLimiter:
    """Exponential lockout for failed unlocks: 5s, 10s, 20s ... capped at 15 min.

    The 3rd consecutive failure starts the lockout. In-memory on purpose: it protects the UI
    path (shoulder surfers, other local users, scripts). Offline attacks on the vault *file*
    are what Argon2 is for. Restarting the app resets the counter.
    """

    FREE_ATTEMPTS = 3
    BASE_DELAY = 5
    MAX_DELAY = 15 * 60

    def __init__(self, clock: Callable[[], float]):
        self.clock = clock
        self.mutex = threading.Lock()
        self.failures = 0
        self.blocked_until = 0.0

    def blocked_for(self) -> int:
        with self.mutex:
            return max(0, math.ceil(self.blocked_until - self.clock()))

    def record_failure(self) -> None:
        with self.mutex:
            self.failures += 1
            if self.failures >= self.FREE_ATTEMPTS:
                exponent = self.failures - self.FREE_ATTEMPTS
                delay = min(self.BASE_DELAY * 2**exponent, self.MAX_DELAY)
                self.blocked_until = self.clock() + delay

    def record_success(self) -> None:
        with self.mutex:
            self.failures = 0
            self.blocked_until = 0.0


# ---- session state -------------------------------------------------------------------------


class SessionState:
    """Holds the (single) unlocked vault, the session token and its CSRF token."""

    def __init__(self, vault_path: Path, auto_lock_seconds: int, clock: Callable[[], float]):
        self.vault = Vault(vault_path)
        self.ttl = auto_lock_seconds
        self.clock = clock
        self.mutex = threading.RLock()
        self.token: str | None = None
        self.csrf: str | None = None
        self.last_activity = 0.0

    def start(self) -> tuple[str, str]:
        """New session: fresh cookie token and CSRF token on every unlock."""
        with self.mutex:
            self.token = secrets.token_urlsafe(32)
            self.csrf = secrets.token_urlsafe(32)
            self.last_activity = self.clock()
            return self.token, self.csrf

    def lock(self) -> None:
        with self.mutex:
            self.vault.lock()
            self.token = None
            self.csrf = None

    def check_idle(self) -> None:
        with self.mutex:
            if self.token is not None and self.clock() - self.last_activity > self.ttl:
                self.lock()

    def touch(self) -> None:
        with self.mutex:
            self.last_activity = self.clock()

    def authenticate(self, cookie: str | None, touch: bool = True) -> bool:
        with self.mutex:
            self.check_idle()
            if not (self.token and cookie and self.vault.is_unlocked):
                return False
            if not secrets.compare_digest(self.token.encode(), cookie.encode()):
                return False
            if touch:
                self.touch()
            return True

    def csrf_ok(self, supplied: str | None) -> bool:
        with self.mutex:
            if not (self.csrf and supplied):
                return False
            return secrets.compare_digest(self.csrf.encode(), supplied.encode())

    def seconds_left(self) -> int:
        return max(0, int(self.ttl - (self.clock() - self.last_activity)))


# ---- body size cap (pure ASGI so it also covers chunked uploads) ---------------------------


class BodyLimitMiddleware:
    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def _reject(self, scope, receive, send) -> None:
        response = JSONResponse(
            {"detail": "request too large"}, status_code=413, headers=SECURITY_HEADERS
        )
        await response(scope, receive, send)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        for key, value in scope["headers"]:
            if key == b"content-length":
                try:
                    too_big = int(value) > self.max_bytes
                except ValueError:
                    too_big = True
                if too_big:
                    await self._reject(scope, receive, send)
                    return

        total = 0
        rejected = False

        async def limited_receive():
            nonlocal total, rejected
            if rejected:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                total += len(message.get("body", b""))
                if total > self.max_bytes:
                    rejected = True
                    await self._reject(scope, receive, send)
                    return {"type": "http.disconnect"}
            return message

        async def guarded_send(message):
            if not rejected:  # after a 413 the app's own (error) response is dropped
                await send(message)

        await self.app(scope, limited_receive, guarded_send)


# ---- app factory ---------------------------------------------------------------------------


def create_app(
    vault_path: str | Path,
    *,
    allowed_hosts: set[str],
    auto_lock_seconds: int = 300,
    kdf_params: KdfParams | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> FastAPI:
    state = SessionState(Path(vault_path), auto_lock_seconds, clock)
    limiter = AttemptLimiter(clock)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        async def watchdog() -> None:
            while True:
                await asyncio.sleep(5)
                state.check_idle()

        task = asyncio.create_task(watchdog())
        try:
            yield
        finally:
            task.cancel()
            state.lock()

    # No /docs, /redoc or /openapi.json: less surface, nothing to leak.
    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.session = state  # lets the desktop shell lock the vault (e.g. on minimize)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        if request.headers.get("host", "") not in allowed_hosts:
            return JSONResponse({"detail": "invalid host"}, status_code=400)
        if request.method not in SAFE_METHODS:
            origin = request.headers.get("origin")
            if origin is not None and urlparse(origin).netloc not in allowed_hosts:
                return JSONResponse({"detail": "cross-origin request blocked"}, status_code=403)
            site = request.headers.get("sec-fetch-site")  # sent by every modern browser
            if site is not None and site not in ("same-origin", "none"):
                return JSONResponse({"detail": "cross-site request blocked"}, status_code=403)
        response = await call_next(request)
        response.headers.update(SECURITY_HEADERS)
        return response

    app.add_middleware(BodyLimitMiddleware, max_bytes=MAX_BODY_BYTES)  # outermost

    @app.exception_handler(VaultError)
    async def vault_error(_: Request, exc: VaultError):
        return JSONResponse({"detail": str(exc)}, status_code=_ERROR_STATUS.get(type(exc), 400))

    def require_session(request: Request, pm_session: str | None = Cookie(default=None)) -> None:
        if not state.authenticate(pm_session, touch=False):
            raise HTTPException(status_code=401, detail="vault is locked")
        if request.method not in SAFE_METHODS and not state.csrf_ok(
            request.headers.get(CSRF_HEADER)
        ):
            raise HTTPException(status_code=403, detail="missing or invalid CSRF token")
        state.touch()  # only a fully valid request counts as activity

    authed = [Depends(require_session)]

    # ---- session endpoints -----------------------------------------------------------------

    @app.get("/api/status")
    def status(pm_session: str | None = Cookie(default=None)):
        # touch=False: polling the status must NOT keep the session alive.
        ok = state.authenticate(pm_session, touch=False)
        return {
            "vault_exists": state.vault.path.exists(),
            "unlocked": ok,
            "seconds_left": state.seconds_left() if ok else None,
            "csrf_token": state.csrf if ok else None,  # only ever given to the cookie holder
        }

    @app.post("/api/init")
    def init(body: MasterIn, response: Response):
        with state.mutex:
            state.vault = Vault.create(state.vault.path, body.master_password, kdf_params)
            token, csrf = state.start()
        _set_cookie(response, token)
        return {"unlocked": True, "csrf_token": csrf}

    @app.post("/api/unlock")
    def unlock(body: MasterIn, response: Response):
        wait = limiter.blocked_for()
        if wait > 0:  # reject before doing any Argon2 work
            raise HTTPException(
                status_code=429,
                detail=f"too many failed attempts, try again in {wait}s",
                headers={"Retry-After": str(wait)},
            )
        with state.mutex:
            try:
                state.vault.unlock(body.master_password)
            except InvalidPassword:
                limiter.record_failure()
                raise
            limiter.record_success()
            token, csrf = state.start()
        _set_cookie(response, token)
        return {"unlocked": True, "csrf_token": csrf}

    @app.post("/api/lock", dependencies=authed)
    def lock():
        state.lock()
        return {"unlocked": False}

    @app.post("/api/ping", dependencies=authed)
    def ping():
        return {"ok": True}

    # ---- entries ---------------------------------------------------------------------------

    @app.get("/api/entries", dependencies=authed)
    def list_entries(q: str = Query("", max_length=200)):
        with state.mutex:
            return [_summary(e) for e in state.vault.search(q)]

    @app.post("/api/entries", dependencies=authed, status_code=201)
    def create_entry(body: EntryIn):
        with state.mutex:
            entry = state.vault.add(
                body.name,
                username=body.username,
                password=body.password,
                url=body.url,
                notes=body.notes,
            )
        return _summary(entry)

    @app.get("/api/entries/{name:path}", dependencies=authed)
    def get_entry(name: str):
        with state.mutex:
            return asdict(state.vault.get(name))

    @app.put("/api/entries/{name:path}", dependencies=authed)
    def update_entry(name: str, body: EntryUpdate):
        fields = body.model_dump(exclude_none=True)
        if not fields:
            raise HTTPException(status_code=422, detail="nothing to update")
        with state.mutex:
            return _summary(state.vault.update(name, **fields))

    @app.delete("/api/entries/{name:path}", dependencies=authed)
    def delete_entry(name: str):
        with state.mutex:
            state.vault.delete(name)
        return {"deleted": name}

    @app.get("/api/generate")
    def generate(length: int = Query(20, ge=8, le=128), symbols: bool = True):
        password = generate_password(length, symbols)
        bits = estimate_entropy_bits(password)
        return {"password": password, "bits": round(bits), "label": strength_label(bits)}

    # Static frontend last, so /api/* routes win.
    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
    return app


def _set_cookie(response: Response, token: str) -> None:
    # Secure flag omitted on purpose: the UI is served over plain http on loopback.
    response.set_cookie(COOKIE_NAME, token, httponly=True, samesite="strict", path="/")


def run(
    vault_path: str | Path,
    host: str = "127.0.0.1",
    port: int = 8765,
    auto_lock_seconds: int = 300,
    open_browser: bool = True,
) -> None:
    if host not in LOOPBACK_HOSTS:
        raise ValueError("the web UI only binds to loopback (127.0.0.1, localhost or ::1)")
    allowed = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}
    app = create_app(vault_path, allowed_hosts=allowed, auto_lock_seconds=auto_lock_seconds)
    url = f"http://localhost:{port}"
    print(f"PasswordManager UI on {url}  (auto-lock {auto_lock_seconds}s, Ctrl+C to stop)")
    if open_browser:
        threading.Timer(1.0, webbrowser.open, args=(url,)).start()
    uvicorn.run(app, host=host, port=port, log_level="warning", server_header=False)
