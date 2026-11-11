"""Single-instance guard and "bring the running window forward" for the desktop app.

Two app instances on one vault would each save their own in-memory copy and the second writer
would silently discard the first one's changes, so a second launch (for example from a global
hotkey) must not start a second app. It focuses the existing window instead.

Windows only; elsewhere this is a no-op (acquire() always succeeds).
"""

from __future__ import annotations

import ctypes
import hashlib
import sys
from collections.abc import Callable
from pathlib import Path

ERROR_ALREADY_EXISTS = 183
SW_SHOW = 5
SW_RESTORE = 9
VK_MENU = 0x12  # the Alt key
KEYEVENTF_KEYUP = 0x0002


def instance_name(vault_path: str | Path) -> str:
    """One mutex per vault file (case-insensitive path), per Windows session."""
    normalized = str(Path(vault_path).resolve()).lower()
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]
    return f"Local\\PasswordManager-{digest}"


def _last_error() -> int:
    return ctypes.get_last_error()  # exists only on Windows, so resolve it lazily


def _load_windows():
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.CreateMutexW.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    user32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
    user32.FindWindowW.restype = wintypes.HWND
    user32.IsIconic.argtypes = [wintypes.HWND]
    user32.IsIconic.restype = wintypes.BOOL
    user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    user32.ShowWindow.restype = wintypes.BOOL
    user32.BringWindowToTop.argtypes = [wintypes.HWND]
    user32.BringWindowToTop.restype = wintypes.BOOL
    user32.SetForegroundWindow.argtypes = [wintypes.HWND]
    user32.SetForegroundWindow.restype = wintypes.BOOL
    user32.keybd_event.argtypes = [wintypes.BYTE, wintypes.BYTE, wintypes.DWORD, ctypes.c_size_t]
    user32.keybd_event.restype = None
    return kernel32, user32


class SingleInstance:
    def __init__(
        self,
        name: str,
        kernel32=None,
        user32=None,
        get_last_error: Callable[[], int] | None = None,
    ):
        self.name = name
        self._handle = None
        if kernel32 is None or user32 is None:
            kernel32 = user32 = None
            if sys.platform == "win32":
                try:
                    kernel32, user32 = _load_windows()
                except (OSError, AttributeError):
                    kernel32 = user32 = None  # fail open: never block the app from starting
        self._kernel32, self._user32 = kernel32, user32
        self._get_last_error = get_last_error or _last_error

    @property
    def supported(self) -> bool:
        return self._kernel32 is not None and self._user32 is not None

    def acquire(self) -> bool:
        """True if we are the first instance (or the platform can't tell)."""
        if not self.supported:
            return True
        handle = self._kernel32.CreateMutexW(None, False, self.name)
        if not handle:
            return True  # fail open; the save-time change check still protects the data
        if self._get_last_error() == ERROR_ALREADY_EXISTS:
            self._kernel32.CloseHandle(handle)
            return False
        self._handle = handle
        return True

    def release(self) -> None:
        if self._handle is not None and self.supported:
            self._kernel32.CloseHandle(self._handle)
        self._handle = None

    def focus_existing(self, window_title: str) -> bool:
        """Restore and raise the running instance's window. False if it can't be found."""
        if not self.supported:
            return False
        hwnd = self._user32.FindWindowW(None, window_title)
        if not hwnd:
            return False
        self._user32.ShowWindow(hwnd, SW_RESTORE if self._user32.IsIconic(hwnd) else SW_SHOW)
        # A tap on Alt makes Windows let SetForegroundWindow through instead of just flashing
        # the taskbar button.
        self._user32.keybd_event(VK_MENU, 0, 0, 0)
        self._user32.keybd_event(VK_MENU, 0, KEYEVENTF_KEYUP, 0)
        self._user32.BringWindowToTop(hwnd)
        return bool(self._user32.SetForegroundWindow(hwnd))
