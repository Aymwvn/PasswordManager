"""Vault: encrypted storage + entry CRUD. No UI code in here."""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
import time
from dataclasses import asdict, dataclass, replace
from pathlib import Path

from . import crypto
from .crypto import KdfParams

MIN_MASTER_LENGTH = 12
EDITABLE_FIELDS = {"username", "password", "url", "notes"}


class VaultError(Exception):
    """Base class for vault errors."""


class VaultExists(VaultError): ...
class VaultNotFound(VaultError): ...
class VaultLocked(VaultError): ...
class InvalidPassword(VaultError): ...
class VaultCorrupted(VaultError): ...
class WeakMasterPassword(VaultError): ...
class EntryExists(VaultError): ...
class EntryNotFound(VaultError): ...


@dataclass
class Entry:
    name: str
    username: str = ""
    password: str = ""
    url: str = ""
    notes: str = ""
    created: int = 0
    updated: int = 0


class Vault:
    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path)
        self._key: bytes | None = None
        self._salt: bytes = b""
        self._params = KdfParams()
        self._entries: dict[str, Entry] = {}

    # ---- lifecycle -------------------------------------------------------------------------

    @classmethod
    def create(
        cls, path: str | os.PathLike[str], master_password: str, params: KdfParams | None = None
    ) -> Vault:
        vault = cls(path)
        if vault.path.exists():
            raise VaultExists(f"vault already exists at {vault.path}")
        if len(master_password) < MIN_MASTER_LENGTH:
            raise WeakMasterPassword(
                f"master password must be at least {MIN_MASTER_LENGTH} characters"
            )
        vault._params = params or KdfParams()
        vault._salt = crypto.new_salt()
        vault._key = crypto.derive_key(master_password, vault._salt, vault._params)
        vault.save()
        return vault

    def unlock(self, master_password: str) -> None:
        if not self.path.exists():
            raise VaultNotFound(f"no vault at {self.path}")
        try:
            plaintext, key, header = crypto.decrypt(master_password, self.path.read_bytes())
        except crypto.DecryptionError as exc:
            raise InvalidPassword(str(exc)) from exc
        except crypto.InvalidFormat as exc:
            raise VaultCorrupted(str(exc)) from exc
        try:
            data = json.loads(plaintext)
            entries = {name: Entry(**raw) for name, raw in data["entries"].items()}
        except (ValueError, KeyError, TypeError) as exc:
            raise VaultCorrupted("vault payload is malformed") from exc
        self._key, self._salt, self._params = key, header.salt, header.params
        self._entries = entries

    def lock(self) -> None:
        """Drop the key and entries. NOTE: Python can't guarantee secure memory wiping;
        this removes our references, it does not scrub RAM. (See docs/THREAT_MODEL.md.)"""
        self._key = None
        self._entries = {}

    @property
    def is_unlocked(self) -> bool:
        return self._key is not None

    def _require_unlocked(self) -> None:
        if self._key is None:
            raise VaultLocked("vault is locked")

    # ---- persistence -----------------------------------------------------------------------

    def save(self) -> None:
        self._require_unlocked()
        payload = json.dumps({"entries": {n: asdict(e) for n, e in self._entries.items()}})
        blob = crypto.encrypt(self._key, payload.encode("utf-8"), self._salt, self._params)
        self._atomic_write(blob)

    def _atomic_write(self, blob: bytes) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".vault-")  # created 0600
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(blob)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)  # atomic: never leaves a half-written vault
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise

    # ---- entries ---------------------------------------------------------------------------

    def add(self, name: str, **fields: str) -> Entry:
        self._require_unlocked()
        if name in self._entries:
            raise EntryExists(f"entry '{name}' already exists")
        now = int(time.time())
        entry = Entry(name=name, created=now, updated=now, **fields)
        self._entries[name] = entry
        self.save()
        return replace(entry)

    def get(self, name: str) -> Entry:
        self._require_unlocked()
        try:
            return replace(self._entries[name])
        except KeyError:
            raise EntryNotFound(f"no entry named '{name}'") from None

    def update(self, name: str, **fields: str) -> Entry:
        self._require_unlocked()
        unknown = set(fields) - EDITABLE_FIELDS
        if unknown:
            raise ValueError(f"cannot edit: {', '.join(sorted(unknown))}")
        if name not in self._entries:
            raise EntryNotFound(f"no entry named '{name}'")
        entry = self._entries[name]
        for key, value in fields.items():
            setattr(entry, key, value)
        entry.updated = int(time.time())
        self.save()
        return replace(entry)

    def delete(self, name: str) -> None:
        self._require_unlocked()
        if self._entries.pop(name, None) is None:
            raise EntryNotFound(f"no entry named '{name}'")
        self.save()

    def list_names(self) -> list[str]:
        self._require_unlocked()
        return sorted(self._entries, key=str.lower)

    def search(self, query: str) -> list[Entry]:
        """Case-insensitive match on name, username, url, notes (never the password)."""
        self._require_unlocked()
        q = query.lower()
        hits = [
            replace(e)
            for e in self._entries.values()
            if any(q in field.lower() for field in (e.name, e.username, e.url, e.notes))
        ]
        return sorted(hits, key=lambda e: e.name.lower())
