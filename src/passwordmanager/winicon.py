"""Window icon and taskbar identity for the desktop app (Windows only; a no-op elsewhere).

pm-app.exe is a Python launcher, so without this Windows shows the generic Python icon in the
title bar and taskbar. We load our own .ico into the running window, and give the process its
own AppUserModelID so the taskbar doesn't group it with other Python programs.
"""

from __future__ import annotations

import ctypes
import sys
from pathlib import Path

ICON_PATH = Path(__file__).parent / "ui" / "static" / "icon.ico"
DEFAULT_APP_ID = "Aymwvn.PasswordManager"

WM_SETICON = 0x0080
ICON_SMALL, ICON_BIG = 0, 1
IMAGE_ICON = 1
LR_LOADFROMFILE = 0x0010
SM_CXICON, SM_CYICON, SM_CXSMICON, SM_CYSMICON = 11, 12, 49, 50


def _load_user32():
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
    user32.FindWindowW.restype = wintypes.HWND
    user32.GetSystemMetrics.argtypes = [ctypes.c_int]
    user32.GetSystemMetrics.restype = ctypes.c_int
    user32.LoadImageW.argtypes = [
        wintypes.HINSTANCE,
        wintypes.LPCWSTR,
        wintypes.UINT,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.UINT,
    ]
    user32.LoadImageW.restype = wintypes.HANDLE
    user32.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    user32.SendMessageW.restype = ctypes.c_ssize_t
    return user32


def _load_shell32():
    from ctypes import wintypes

    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    shell32.SetCurrentProcessExplicitAppUserModelID.argtypes = [wintypes.LPCWSTR]
    shell32.SetCurrentProcessExplicitAppUserModelID.restype = ctypes.c_long
    return shell32


def set_app_user_model_id(app_id: str = DEFAULT_APP_ID, shell32=None) -> bool:
    """Call before the window exists. True if Windows accepted the ID (HRESULT S_OK)."""
    if shell32 is None:
        if sys.platform != "win32":
            return False
        try:
            shell32 = _load_shell32()
        except (OSError, AttributeError):
            return False
    return shell32.SetCurrentProcessExplicitAppUserModelID(app_id) == 0


def set_window_icon(window_title: str, icon_path: str | Path = ICON_PATH, user32=None) -> bool:
    """Give the top-level window with this exact title our big and small icons."""
    path = Path(icon_path)
    if not path.is_file():
        return False
    if user32 is None:
        if sys.platform != "win32":
            return False
        try:
            user32 = _load_user32()
        except (OSError, AttributeError):
            return False
    hwnd = user32.FindWindowW(None, window_title)
    if not hwnd:
        return False

    def load(width_metric: int, height_metric: int):
        return user32.LoadImageW(
            None, str(path), IMAGE_ICON,
            user32.GetSystemMetrics(width_metric), user32.GetSystemMetrics(height_metric),
            LR_LOADFROMFILE,
        )

    big, small = load(SM_CXICON, SM_CYICON), load(SM_CXSMICON, SM_CYSMICON)
    if big:
        user32.SendMessageW(hwnd, WM_SETICON, ICON_BIG, big)
    if small:
        user32.SendMessageW(hwnd, WM_SETICON, ICON_SMALL, small)
    return bool(big or small)
