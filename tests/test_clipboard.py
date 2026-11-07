import sys

import pytest

from passwordmanager.core import clipboard as cb
from passwordmanager.core.clipboard import ClipboardError, ClipboardGuard, WindowsClipboard

from .conftest import FakeClipboard

# ---- ClipboardGuard: "clear only if still ours" -----------------------------------------------


class FakeTimer:
    def __init__(self, interval, function):
        self.interval, self.function = interval, function
        self.started = self.cancelled = False
        self.daemon = False

    def start(self):
        self.started = True

    def cancel(self):
        self.cancelled = True


@pytest.fixture
def timers():
    return []


@pytest.fixture
def guard(timers):
    backend = FakeClipboard()

    def factory(interval, function):
        timers.append(FakeTimer(interval, function))
        return timers[-1]

    return ClipboardGuard(backend, clear_after=15, timer_factory=factory)


def test_copy_schedules_a_daemon_timer(guard, timers):
    guard.copy("s3cret")
    assert guard.backend.text == "s3cret"
    assert (timers[0].interval, timers[0].started, timers[0].daemon) == (15, True, True)


def test_timer_clears_the_clipboard_when_it_is_still_ours(guard, timers):
    guard.copy("s3cret")
    timers[0].function()
    assert guard.backend.text == ""


def test_something_the_user_copied_meanwhile_is_never_wiped(guard, timers):
    guard.copy("s3cret")
    guard.backend.user_copies("my shopping list")
    timers[0].function()
    assert guard.backend.text == "my shopping list"
    assert guard.clear_if_ours() is False


def test_a_new_copy_cancels_the_previous_timer(guard, timers):
    guard.copy("first")
    guard.copy("second")
    assert timers[0].cancelled and not timers[1].cancelled
    timers[1].function()
    assert guard.backend.text == ""


def test_clear_if_ours_is_idempotent_and_safe_before_any_copy(guard):
    assert guard.clear_if_ours() is False
    guard.copy("x")
    assert guard.clear_if_ours() is True
    assert guard.clear_if_ours() is False


def test_a_failed_write_leaves_nothing_pending(timers):
    class Broken(FakeClipboard):
        def set_secret(self, text):
            raise ClipboardError("busy")

    guard = ClipboardGuard(Broken(), timer_factory=lambda i, f: FakeTimer(i, f))
    with pytest.raises(ClipboardError):
        guard.copy("x")
    assert guard.clear_if_ours() is False


# ---- WindowsClipboard against a fake Win32 layer ------------------------------------------------


class FakeWin32:
    """Plays user32 + kernel32 and records what the code asks of them."""

    def __init__(self, busy=0, fail_alloc=False, fail_lock=False, fail_empty=False):
        self.calls, self.freed, self.sleeps = [], [], []
        self.busy, self.fail_alloc, self.fail_lock, self.fail_empty = busy, fail_alloc, fail_lock, fail_empty
        self.fail_format = None
        self.sequence = 1000
        self.format_ids, self.clipboard, self.memory = {}, {}, {}
        self._next_handle = 0x10

    def _record(self, name):
        self.calls.append(name)

    # user32
    def RegisterClipboardFormatW(self, name):  # noqa: N802
        return self.format_ids.setdefault(name, 0xC000 + len(self.format_ids))

    def OpenClipboard(self, _hwnd):  # noqa: N802
        self._record("OpenClipboard")
        if self.busy > 0:
            self.busy -= 1
            return 0
        return 1

    def CloseClipboard(self):  # noqa: N802
        self._record("CloseClipboard")
        return 1

    def EmptyClipboard(self):  # noqa: N802
        self._record("EmptyClipboard")
        self.clipboard.clear()
        self.sequence += 1
        return 0 if self.fail_empty else 1

    def SetClipboardData(self, fmt, handle):  # noqa: N802
        self._record("SetClipboardData")
        if fmt == self.fail_format:
            return 0
        self.clipboard[fmt] = self.memory[handle]
        self.sequence += 1
        return handle

    def GetClipboardSequenceNumber(self):  # noqa: N802
        return self.sequence

    # kernel32
    def GlobalAlloc(self, _flags, size):  # noqa: N802
        if self.fail_alloc:
            return 0
        self._next_handle += 0x10
        self.memory[self._next_handle] = b"\x00" * size
        return self._next_handle

    def GlobalLock(self, handle):  # noqa: N802
        return 0 if self.fail_lock else handle

    def GlobalUnlock(self, _handle):  # noqa: N802
        return 1

    def GlobalFree(self, handle):  # noqa: N802
        self.freed.append(handle)
        return 0

    def memmove(self, pointer, data, size):
        self.memory[pointer] = bytes(data)[:size]

    def sleep(self, seconds):
        self.sleeps.append(seconds)


def make(**kwargs):
    fake = FakeWin32(**kwargs)
    return fake, WindowsClipboard(user32=fake, kernel32=fake, memmove=fake.memmove, sleep=fake.sleep)


def test_text_is_utf16_with_a_terminating_nul():
    fake, win = make()
    win.set_secret("p\u00e4ssw\u00f6rd\U0001f600")
    assert fake.clipboard[cb.CF_UNICODETEXT] == "p\u00e4ssw\u00f6rd\U0001f600\x00".encode("utf-16-le")


def test_privacy_formats_are_registered_and_set_with_the_right_payloads():
    fake, win = make()
    win.set_secret("secret")
    by_name = {name: fake.clipboard[fake.format_ids[name]] for name, _ in cb.PRIVACY_FORMATS}
    assert by_name["CanIncludeInClipboardHistory"] == b"\x00\x00\x00\x00"
    assert by_name["CanUploadToCloudClipboard"] == b"\x00\x00\x00\x00"
    assert "ExcludeClipboardContentFromMonitorProcessing" in by_name
    assert len(by_name) == 4


def test_call_order_empty_then_write_then_close_then_sequence():
    fake, win = make()
    sequence = win.set_secret("secret")
    assert fake.calls[0] == "OpenClipboard"
    assert fake.calls.index("EmptyClipboard") < fake.calls.index("SetClipboardData")
    assert fake.calls.index("SetClipboardData") < fake.calls.index("CloseClipboard")
    assert sequence == fake.sequence == win.sequence_number()


def test_a_busy_clipboard_is_retried_then_given_up_on():
    fake, win = make(busy=3)
    win.set_secret("secret")
    assert len(fake.sleeps) == 3

    fake, win = make(busy=10_000)
    with pytest.raises(ClipboardError, match="busy"):
        win.set_secret("secret")
    assert "EmptyClipboard" not in fake.calls and "CloseClipboard" not in fake.calls


def test_the_secret_is_never_left_behind_without_its_privacy_flags():
    fake, win = make()
    fake.fail_format = fake.format_ids["CanUploadToCloudClipboard"]
    with pytest.raises(ClipboardError):
        win.set_secret("secret")
    assert fake.clipboard == {}  # emptied again after the partial write
    assert fake.calls[-1] == "CloseClipboard"
    assert fake.freed  # the memory the system refused was released, not leaked


def test_allocation_and_lock_failures_are_clean_errors():
    fake, win = make(fail_alloc=True)
    with pytest.raises(ClipboardError):
        win.set_secret("secret")
    assert fake.calls[-1] == "CloseClipboard"

    fake, win = make(fail_lock=True)
    with pytest.raises(ClipboardError):
        win.set_secret("secret")
    assert fake.freed and fake.clipboard == {}


def test_empty_failure_is_reported():
    _, win = make(fail_empty=True)
    with pytest.raises(ClipboardError):
        win.set_secret("secret")


def test_clear_empties_the_clipboard_and_always_closes_it():
    fake, win = make()
    win.set_secret("secret")
    win.clear()
    assert fake.clipboard == {} and fake.calls[-1] == "CloseClipboard"


def test_unregistrable_formats_are_an_error_not_a_silent_downgrade():
    class NoFormats(FakeWin32):
        def RegisterClipboardFormatW(self, name):  # noqa: N802
            return 0

    fake = NoFormats()
    with pytest.raises(ClipboardError):
        WindowsClipboard(user32=fake, kernel32=fake, memmove=fake.memmove, sleep=fake.sleep)


# ---- default_backend --------------------------------------------------------------------------


def test_no_native_backend_off_windows(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    assert cb.default_backend() is None


def test_native_backend_on_windows_and_graceful_failure(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    sentinel = object()
    monkeypatch.setattr(cb, "WindowsClipboard", lambda: sentinel)
    assert cb.default_backend() is sentinel

    def boom():
        raise OSError("no user32")

    monkeypatch.setattr(cb, "WindowsClipboard", boom)
    assert cb.default_backend() is None
