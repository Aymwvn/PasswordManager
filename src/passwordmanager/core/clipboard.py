"""Clipboard handling for secrets.

On Windows we use the clipboard API directly so that a copied password or 2FA code

  * is flagged to stay out of Windows clipboard history and the cloud clipboard,
  * is cleared after a delay ONLY if nothing else was copied meanwhile (we compare the
    clipboard sequence number instead of reading the clipboard back),
  * is cleared again when the vault locks or the app exits.

The exclusion formats are a cooperative convention: Windows' own history and cloud features
honour them, but some third-party clipboard managers ignore them (see docs/THREAT_MODEL.md).
Elsewhere (and in plain browsers) callers fall back to the browser clipboard.
"""

from __future__ import annotations

import contextlib
import ctypes
import sys
import threading
import time
from collections.abc import Callable, Iterator
from typing import Protocol

CF_UNICODETEXT = 13
GMEM_MOVEABLE = 0x0002
DEFAULT_CLEAR_SECONDS = 15.0
DWORD_ZERO = b"\x00\x00\x00\x00"

# (registered format name, payload). Names and semantics per Microsoft's "Clipboard Formats":
# DWORD 0 opts out of history / cloud sync; the Exclude... format takes any data.
PRIVACY_FORMATS = (
    ("CanIncludeInClipboardHistory", DWORD_ZERO),
    ("CanUploadToCloudClipboard", DWORD_ZERO),
    ("ExcludeClipboardContentFromMonitorProcessing", DWORD_ZERO),
    ("Clipboard Viewer Ignore", b"\x00"),  # older convention some third-party managers honour
)


class ClipboardError(Exception):
    """The clipboard could not be written or cleared."""


class ClipboardBackend(Protocol):
    def set_secret(self, text: str) -> int:
        """Replace the clipboard with `text`, marked private. Returns the sequence number."""

    def sequence_number(self) -> int:
        """Changes every time anything modifies the clipboard."""

    def clear(self) -> None: ...


class ClipboardGuard:
    """Copy a secret, then clear it later, but only if it is still ours."""

    def __init__(
        self,
        backend: ClipboardBackend,
        clear_after: float = DEFAULT_CLEAR_SECONDS,
        timer_factory: Callable[[float, Callable[[], object]], threading.Timer] = threading.Timer,
    ):
        self.backend = backend
        self.clear_after = clear_after
        self._timer_factory = timer_factory
        self._mutex = threading.Lock()
        self._sequence: int | None = None
        self._timer: threading.Timer | None = None

    def copy(self, text: str) -> None:
        with self._mutex:
            self._cancel_timer()
            self._sequence = None  # if the write fails, nothing is pending
            self._sequence = self.backend.set_secret(text)
            timer = self._timer_factory(self.clear_after, self.clear_if_ours)
            timer.daemon = True
            self._timer = timer
            timer.start()

    def clear_if_ours(self) -> bool:
        """Clear the clipboard if nothing else was copied since we wrote it."""
        with self._mutex:
            self._cancel_timer()
            if self._sequence is None:
                return False
            ours = self.backend.sequence_number() == self._sequence
            if ours:
                self.backend.clear()
            self._sequence = None
            return ours

    def _cancel_timer(self) -> None:
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None


def _declare_signatures(user32, kernel32) -> None:
    """Explicit ctypes prototypes. Without them, 64-bit handles get truncated to 32 bits."""
    from ctypes import wintypes

    user32.OpenClipboard.argtypes = [wintypes.HWND]
    user32.OpenClipboard.restype = wintypes.BOOL
    user32.CloseClipboard.argtypes = []
    user32.CloseClipboard.restype = wintypes.BOOL
    user32.EmptyClipboard.argtypes = []
    user32.EmptyClipboard.restype = wintypes.BOOL
    user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    user32.SetClipboardData.restype = wintypes.HANDLE
    user32.GetClipboardSequenceNumber.argtypes = []
    user32.GetClipboardSequenceNumber.restype = wintypes.DWORD
    user32.RegisterClipboardFormatW.argtypes = [wintypes.LPCWSTR]
    user32.RegisterClipboardFormatW.restype = wintypes.UINT
    kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
    kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalUnlock.restype = wintypes.BOOL
    kernel32.GlobalFree.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalFree.restype = wintypes.HGLOBAL


class WindowsClipboard:
    OPEN_ATTEMPTS = 20
    OPEN_DELAY = 0.025  # another app may hold the clipboard for a moment

    def __init__(
        self,
        user32=None,
        kernel32=None,
        memmove: Callable[[int, bytes, int], object] = ctypes.memmove,
        sleep: Callable[[float], object] = time.sleep,
    ):
        if user32 is None or kernel32 is None:
            user32 = ctypes.WinDLL("user32", use_last_error=True)
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            _declare_signatures(user32, kernel32)
        self._user32, self._kernel32 = user32, kernel32
        self._memmove, self._sleep = memmove, sleep
        self._privacy = []
        for name, payload in PRIVACY_FORMATS:
            format_id = self._user32.RegisterClipboardFormatW(name)
            if not format_id:
                raise ClipboardError(f"could not register the '{name}' clipboard format")
            self._privacy.append((format_id, payload))

    @contextlib.contextmanager
    def _open(self) -> Iterator[None]:
        for _ in range(self.OPEN_ATTEMPTS):
            if self._user32.OpenClipboard(None):
                break
            self._sleep(self.OPEN_DELAY)
        else:
            raise ClipboardError("the clipboard is busy, try again")
        try:
            yield
        finally:
            self._user32.CloseClipboard()

    def _put(self, format_id: int, data: bytes) -> None:
        handle = self._kernel32.GlobalAlloc(GMEM_MOVEABLE, len(data))
        if not handle:
            raise ClipboardError("out of memory")
        pointer = self._kernel32.GlobalLock(handle)
        if not pointer:
            self._kernel32.GlobalFree(handle)
            raise ClipboardError("could not lock clipboard memory")
        self._memmove(pointer, data, len(data))
        self._kernel32.GlobalUnlock(handle)
        if not self._user32.SetClipboardData(format_id, handle):
            self._kernel32.GlobalFree(handle)  # on success the system owns the memory
            raise ClipboardError("could not set clipboard data")

    def set_secret(self, text: str) -> int:
        data = (text + "\x00").encode("utf-16-le")
        with self._open():
            if not self._user32.EmptyClipboard():
                raise ClipboardError("could not empty the clipboard")
            try:
                self._put(CF_UNICODETEXT, data)
                for format_id, payload in self._privacy:
                    self._put(format_id, payload)
            except BaseException:
                # Never leave the secret behind without its privacy flags.
                self._user32.EmptyClipboard()
                raise
        return int(self._user32.GetClipboardSequenceNumber())

    def sequence_number(self) -> int:
        return int(self._user32.GetClipboardSequenceNumber())

    def clear(self) -> None:
        with self._open():
            self._user32.EmptyClipboard()


def default_backend() -> ClipboardBackend | None:
    """The native backend on Windows, otherwise None (callers fall back to the browser)."""
    if sys.platform != "win32":
        return None
    try:
        return WindowsClipboard()
    except (OSError, AttributeError, ClipboardError):
        return None
