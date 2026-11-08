import sys
import types
import urllib.request

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("uvicorn")

from passwordmanager import app as desktop  # noqa: E402


def test_start_server_serves_ui_and_stops(tmp_path):
    srv = desktop.start_server(tmp_path / "v.bin")
    try:
        assert srv.url.startswith("http://127.0.0.1:")
        with urllib.request.urlopen(srv.url + "api/status", timeout=5) as res:  # noqa: S310
            assert res.status == 200
            assert "default-src 'none'" in res.headers["Content-Security-Policy"]
    finally:
        srv.stop()
    with pytest.raises(OSError):
        urllib.request.urlopen(srv.url + "api/status", timeout=2)  # noqa: S310


def test_each_launch_gets_its_own_port(tmp_path):
    a = desktop.start_server(tmp_path / "a.bin")
    b = desktop.start_server(tmp_path / "b.bin")
    try:
        assert a.port != b.port
    finally:
        a.stop()
        b.stop()


class _Event:
    def __init__(self):
        self.handlers = []

    def __iadd__(self, fn):
        self.handlers.append(fn)
        return self

    def fire(self):
        for fn in self.handlers:
            fn()


@pytest.fixture
def fake_webview(monkeypatch):
    calls = {}

    def create_window(title, url, **kwargs):
        calls.update(title=title, url=url, kwargs=kwargs)
        window = types.SimpleNamespace(events=types.SimpleNamespace(minimized=_Event()))
        calls["window"] = window
        return window

    def start(*_a, **_k):
        calls["started"] = True
        with urllib.request.urlopen(calls["url"] + "api/status", timeout=5) as res:  # noqa: S310
            calls["status_during_run"] = res.status
        calls["window"].events.minimized.fire()  # simulate the user minimizing the window

    module = types.ModuleType("webview")
    module.create_window = create_window
    module.start = start
    monkeypatch.setitem(sys.modules, "webview", module)
    return calls


def test_run_app_opens_window_and_cleans_up(tmp_path, fake_webview):
    desktop.run_app(tmp_path / "v.bin")
    assert fake_webview["title"] == desktop.WINDOW_TITLE
    assert fake_webview["url"].startswith("http://127.0.0.1:")
    assert fake_webview["status_during_run"] == 200
    assert len(fake_webview["window"].events.minimized.handlers) == 1
    with pytest.raises(OSError):  # server is gone after the window closes
        urllib.request.urlopen(fake_webview["url"] + "api/status", timeout=2)  # noqa: S310


def test_lock_on_minimize_can_be_disabled(tmp_path, fake_webview):
    desktop.run_app(tmp_path / "v.bin", lock_on_minimize=False)
    assert fake_webview["window"].events.minimized.handlers == []


def test_main_reports_missing_pywebview(tmp_path, monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, "webview", None)  # makes `import webview` raise ImportError
    assert desktop.main(["--vault", str(tmp_path / "v.bin")]) == 1
    assert "pip install" in capsys.readouterr().err


# ---- single instance ----------------------------------------------------------------------------


class FakeInstance:
    def __init__(self, first=True):
        self.first, self.focused, self.released = first, [], 0

    def acquire(self):
        return self.first

    def focus_existing(self, title):
        self.focused.append(title)
        return True

    def release(self):
        self.released += 1


def test_a_second_launch_focuses_the_running_window_and_starts_nothing(tmp_path, fake_webview):
    instance = FakeInstance(first=False)
    assert desktop.run_app(tmp_path / "v.bin", single_instance=instance) is False
    assert instance.focused == [desktop.WINDOW_TITLE]
    assert "started" not in fake_webview and "title" not in fake_webview


def test_the_first_launch_holds_the_lock_until_the_window_closes(tmp_path, fake_webview):
    instance = FakeInstance()
    assert desktop.run_app(tmp_path / "v.bin", single_instance=instance) is True
    assert fake_webview["started"] and instance.released == 1


def test_the_lock_is_released_even_if_the_window_crashes(tmp_path, fake_webview, monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("webview failed")

    monkeypatch.setattr(sys.modules["webview"], "start", boom)
    instance = FakeInstance()
    with pytest.raises(RuntimeError):
        desktop.run_app(tmp_path / "v.bin", single_instance=instance)
    assert instance.released == 1


def test_window_title_is_not_a_plain_folder_name():
    assert desktop.WINDOW_TITLE != "PasswordManager"
