import sys
from pathlib import Path

from passwordmanager import winicon as wi

REPO = Path(__file__).resolve().parents[1]


class FakeUser32:
    def __init__(self, windows=None, fail_loads=()):
        self.windows = windows or {}
        self.fail_loads = set(fail_loads)
        self.sent, self.loaded = [], []

    def FindWindowW(self, _cls, title):  # noqa: N802
        return self.windows.get(title, 0)

    def GetSystemMetrics(self, index):  # noqa: N802
        return {wi.SM_CXICON: 32, wi.SM_CYICON: 32, wi.SM_CXSMICON: 16, wi.SM_CYSMICON: 16}[index]

    def LoadImageW(self, _inst, path, kind, cx, cy, flags):  # noqa: N802
        self.loaded.append((path, kind, cx, cy, flags))
        return 0 if cx in self.fail_loads else 1000 + cx

    def SendMessageW(self, hwnd, message, wparam, lparam):  # noqa: N802
        self.sent.append((hwnd, message, wparam, lparam))
        return 0


class FakeShell32:
    def __init__(self, result=0):
        self.result, self.ids = result, []

    def SetCurrentProcessExplicitAppUserModelID(self, app_id):  # noqa: N802
        self.ids.append(app_id)
        return self.result


def test_both_icon_sizes_are_loaded_from_the_file_and_sent_to_the_window():
    user32 = FakeUser32(windows={"My Window": 0x77})
    assert wi.set_window_icon("My Window", wi.ICON_PATH, user32=user32) is True
    sizes = [(cx, cy) for _, _, cx, cy, _ in user32.loaded]
    assert sizes == [(32, 32), (16, 16)]  # the system's own big and small icon sizes
    assert all(kind == wi.IMAGE_ICON and flags == wi.LR_LOADFROMFILE for _, kind, _, _, flags in user32.loaded)
    assert (0x77, wi.WM_SETICON, wi.ICON_BIG, 1032) in user32.sent
    assert (0x77, wi.WM_SETICON, wi.ICON_SMALL, 1016) in user32.sent


def test_no_window_or_no_file_means_false_and_nothing_is_sent(tmp_path):
    user32 = FakeUser32(windows={})
    assert wi.set_window_icon("Missing", wi.ICON_PATH, user32=user32) is False
    present = FakeUser32(windows={"W": 1})
    assert wi.set_window_icon("W", tmp_path / "nope.ico", user32=present) is False
    assert user32.sent == [] and present.sent == [] and present.loaded == []


def test_a_failed_load_of_one_size_still_applies_the_other():
    user32 = FakeUser32(windows={"W": 5}, fail_loads={32})
    assert wi.set_window_icon("W", wi.ICON_PATH, user32=user32) is True
    assert [m[2] for m in user32.sent] == [wi.ICON_SMALL]
    both_fail = FakeUser32(windows={"W": 5}, fail_loads={32, 16})
    assert wi.set_window_icon("W", wi.ICON_PATH, user32=both_fail) is False


def test_app_user_model_id():
    shell32 = FakeShell32()
    assert wi.set_app_user_model_id(shell32=shell32) is True
    assert shell32.ids == [wi.DEFAULT_APP_ID]
    assert wi.set_app_user_model_id("x", shell32=FakeShell32(result=-2147024809)) is False


def test_no_op_off_windows(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    assert wi.set_window_icon("W") is False
    assert wi.set_app_user_model_id() is False


# ---- the shipped icon files -----------------------------------------------------------------------


def _ico_sizes(data: bytes) -> set[int]:
    count = int.from_bytes(data[4:6], "little")
    return {(data[6 + 16 * i] or 256) for i in range(count)}


def test_the_bundled_icon_is_a_real_multi_size_ico():
    data = wi.ICON_PATH.read_bytes()
    assert data[:4] == b"\x00\x00\x01\x00"
    assert {16, 20, 24, 32, 48, 64, 128, 256} <= _ico_sizes(data)


def test_the_repo_level_icon_matches_the_one_bundled_in_the_package():
    # assets/icon.ico feeds the exe build and the shortcuts; the packaged copy feeds the window.
    assert (REPO / "assets" / "icon.ico").read_bytes() == wi.ICON_PATH.read_bytes()
    assert (REPO / "assets" / "icon.png").read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
