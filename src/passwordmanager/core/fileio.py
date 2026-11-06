"""Atomic, private file writes shared by the vault and the export feature."""

from __future__ import annotations

import contextlib
import os
import tempfile
from pathlib import Path


def atomic_write(path: str | os.PathLike[str], data: bytes, *, make_parents: bool = True) -> None:
    """Write via a temp file in the same directory, fsync, then os.replace.

    A crash can never leave a half-written file, and the temp file is created 0600 by mkstemp.
    """
    target = Path(path)
    if make_parents:
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=".pm-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
