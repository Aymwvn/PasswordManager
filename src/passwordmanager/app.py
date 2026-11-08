"""Desktop shell: the local server on a random loopback port, shown in a native window.

Needs the optional extra:  pip install -e ".[app]"   (pywebview; uses WebView2 on Windows)
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from passwordmanager.singleton import SingleInstance, instance_name

if TYPE_CHECKING:  # the heavy imports happen lazily so a second launch can exit quickly
    import uvicorn
    from fastapi import FastAPI

# Deliberately not just "PasswordManager": a File Explorer window for a folder with that name has
# exactly that title, and the second launch finds the running window by its exact title.
WINDOW_TITLE = "PasswordManager - Local Vault"


def default_vault_path() -> Path:
    env = os.environ.get("PM_VAULT")
    return Path(env) if env else Path.home() / ".passwordmanager" / "vault.bin"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@dataclass
class RunningServer:
    port: int
    app: FastAPI
    server: uvicorn.Server
    thread: threading.Thread

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/"

    def stop(self) -> None:
        self.server.should_exit = True  # lifespan shutdown also locks the vault
        self.thread.join(timeout=5)


def start_server(
    vault_path: str | Path, auto_lock_seconds: int = 300, startup_timeout: float = 10.0
) -> RunningServer:
    import uvicorn

    from passwordmanager.ui.server import create_app

    port = _free_port()
    allowed = {f"127.0.0.1:{port}", f"localhost:{port}"}
    app = create_app(vault_path, allowed_hosts=allowed, auto_lock_seconds=auto_lock_seconds)
    config = uvicorn.Config(
        app, host="127.0.0.1", port=port, log_level="warning", server_header=False
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, name="pm-server", daemon=True)
    thread.start()
    deadline = time.monotonic() + startup_timeout
    while not server.started:
        if not thread.is_alive() or time.monotonic() > deadline:
            raise RuntimeError("the local server failed to start")
        time.sleep(0.05)
    return RunningServer(port, app, server, thread)


def run_app(
    vault_path: str | Path,
    auto_lock_seconds: int = 300,
    lock_on_minimize: bool = True,
    single_instance: SingleInstance | None = None,
) -> bool:
    """Open the app. Returns False if one was already running for this vault; in that case its
    window is brought to the front and nothing else starts."""
    instance = single_instance or SingleInstance(instance_name(vault_path))
    if not instance.acquire():
        instance.focus_existing(WINDOW_TITLE)
        return False
    try:
        import webview  # imported late so the rest of the package works without pywebview

        srv = start_server(vault_path, auto_lock_seconds)
        try:
            window = webview.create_window(
                WINDOW_TITLE, srv.url, width=1100, height=720, min_size=(820, 540)
            )
            if lock_on_minimize:
                try:
                    window.events.minimized += srv.app.state.session.lock
                except AttributeError:  # older pywebview without the minimized event
                    pass
            webview.start()
        finally:
            srv.stop()
    finally:
        instance.release()
    return True


def _fatal(message: str) -> None:
    if sys.stderr:
        print(f"error: {message}", file=sys.stderr)
    elif sys.platform == "win32":  # windowed .exe has no console, so show a dialog instead
        import ctypes

        ctypes.windll.user32.MessageBoxW(0, message, WINDOW_TITLE, 0x10)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pm-app", description="PasswordManager desktop app")
    parser.add_argument("--vault", help="vault file path (default: ~/.passwordmanager/vault.bin)")
    parser.add_argument("--auto-lock", type=int, default=300, metavar="SECONDS")
    parser.add_argument("--no-lock-on-minimize", action="store_true")
    args = parser.parse_args(argv)
    try:
        run_app(
            Path(args.vault) if args.vault else default_vault_path(),
            auto_lock_seconds=args.auto_lock,
            lock_on_minimize=not args.no_lock_on_minimize,
        )
    except ImportError as exc:
        _fatal(f'missing dependency ({exc.name}). Install with: pip install -e ".[app]"')
        return 1
    except Exception as exc:  # GUI entry point: report anything instead of dying silently
        _fatal(str(exc))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
