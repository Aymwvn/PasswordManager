import sys

from passwordmanager import singleton as sg
from passwordmanager.singleton import SingleInstance, instance_name


class FakeWin32:
    def __init__(self, mutex_exists=False, mutex_fails=False, windows=None, minimized=False,
                 foreground_ok=True):
        self.calls, self.created, self.closed = [], [], []
        self.mutex_exists, self.mutex_fails = mutex_exists, mutex_fails
        self.windows = windows or {}
        self.minimized, self.foreground_ok = minimized, foreground_ok

    def last_error(self):
        return sg.ERROR_ALREADY_EXISTS if self.mutex_exists else 0

    def CreateMutexW(self, _attrs, _owner, name):  # noqa: N802
        self.created.append(name)
        return 0 if self.mutex_fails else 0x44

    def CloseHandle(self, handle):  # noqa: N802
        self.closed.append(handle)

    def FindWindowW(self, _cls, title):  # noqa: N802
        self.calls.append(("FindWindowW", title))
        return self.windows.get(title, 0)

    def IsIconic(self, _hwnd):  # noqa: N802
        return self.minimized

    def ShowWindow(self, hwnd, command):  # noqa: N802
        self.calls.append(("ShowWindow", hwnd, command))

    def keybd_event(self, key, _scan, flags, _extra):
        self.calls.append(("keybd_event", key, flags))

    def BringWindowToTop(self, hwnd):  # noqa: N802
        self.calls.append(("BringWindowToTop", hwnd))

    def SetForegroundWindow(self, hwnd):  # noqa: N802
        self.calls.append(("SetForegroundWindow", hwnd))
        return self.foreground_ok


def make(**kwargs):
    fake = FakeWin32(**kwargs)
    return fake, SingleInstance("Local\\x", kernel32=fake, user32=fake, get_last_error=fake.last_error)


def test_the_first_instance_acquires_and_releases_the_mutex():
    fake, instance = make()
    assert instance.acquire() is True
    instance.release()
    instance.release()  # idempotent
    assert fake.created == ["Local\\x"] and fake.closed == [0x44]


def test_a_second_instance_is_refused_and_does_not_leak_its_handle():
    fake, instance = make(mutex_exists=True)
    assert instance.acquire() is False
    assert fake.closed == [0x44]
    instance.release()
    assert fake.closed == [0x44]  # nothing more to close: we never owned it


def test_failing_to_create_the_mutex_fails_open():
    _, instance = make(mutex_fails=True)
    assert instance.acquire() is True  # better to start than to lock the user out


def test_instance_names_are_stable_per_vault_and_case_insensitive(tmp_path):
    a = instance_name(tmp_path / "Vault.bin")
    assert a == instance_name(tmp_path / "vault.BIN")
    assert a != instance_name(tmp_path / "other.bin")
    assert a.startswith("Local\\PasswordManager-")


def test_focus_restores_a_minimized_window_and_raises_it():
    fake, instance = make(windows={"My Title": 0x99}, minimized=True)
    assert instance.focus_existing("My Title") is True
    assert ("FindWindowW", "My Title") in fake.calls
    assert ("ShowWindow", 0x99, sg.SW_RESTORE) in fake.calls
    names = [c[0] for c in fake.calls]
    assert names.index("keybd_event") < names.index("SetForegroundWindow")  # Alt tap first
    assert fake.calls.count(("keybd_event", sg.VK_MENU, 0)) == 1
    assert fake.calls.count(("keybd_event", sg.VK_MENU, sg.KEYEVENTF_KEYUP)) == 1


def test_focus_of_a_visible_window_just_shows_it():
    fake, instance = make(windows={"My Title": 0x99}, minimized=False)
    instance.focus_existing("My Title")
    assert ("ShowWindow", 0x99, sg.SW_SHOW) in fake.calls


def test_focus_returns_false_when_there_is_no_such_window_or_windows_refuses():
    fake, instance = make(windows={})
    assert instance.focus_existing("Nope") is False
    assert not any(c[0] == "SetForegroundWindow" for c in fake.calls)
    _, refusing = make(windows={"T": 1}, foreground_ok=False)
    assert refusing.focus_existing("T") is False


def test_no_op_off_windows(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    instance = SingleInstance("Local\\x")
    assert instance.supported is False
    assert instance.acquire() is True and instance.focus_existing("T") is False
    instance.release()
