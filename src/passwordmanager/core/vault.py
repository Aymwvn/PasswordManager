"""Vault: encrypted storage + entry CRUD. No UI code in here."""

from __future__ import annotations

import json
import os
import time
import unicodedata
from dataclasses import asdict, dataclass, replace
from pathlib import Path

from . import crypto, totp
from .crypto import KdfParams
from .fileio import atomic_write

MIN_MASTER_LENGTH = 12
EDITABLE_FIELDS = {"username", "password", "url", "notes", "totp"}
FIELD_LIMITS = {
    "name": 200,
    "username": 500,
    "password": 1024,  # nosec B105 - a length limit, not a secret
    "url": 2000,
    "notes": 10_000,
    "totp": 1000,
}
CONFLICT_MODES = ("rename", "skip", "overwrite")


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
class InvalidEntry(VaultError): ...
class InvalidTotpSecret(InvalidEntry): ...
class TotpNotConfigured(VaultError): ...


@dataclass
class Entry:
    name: str
    username: str = ""
    password: str = ""
    url: str = ""
    notes: str = ""
    totp: str = ""  # base32 secret or otpauth://totp/ URI
    created: int = 0
    updated: int = 0


@dataclass
class ImportReport:
    """added = new entries created (renamed ones included); overwritten = existing replaced."""

    added: int = 0
    renamed: int = 0
    skipped: int = 0
    overwritten: int = 0


def validate_entry_fields(**fields: str) -> None:
    """Length limits, non-empty name, and a parseable TOTP secret. Raises InvalidEntry."""
    for key, value in fields.items():
        limit = FIELD_LIMITS.get(key)
        if limit is not None and len(value) > limit:
            raise InvalidEntry(f"{key} is too long (max {limit} characters)")
    if "name" in fields:
        if not fields["name"]:
            raise InvalidEntry("name cannot be empty")
        # Names are single-line labels that also travel in URL paths (/api/entries/{name}); a
        # line break makes the route regex miss, leaving an entry that can't be opened or deleted.
        if any(unicodedata.category(ch) == "Cc" for ch in fields["name"]):
            raise InvalidEntry("name cannot contain control characters such as line breaks")
    if fields.get("totp"):
        try:
            totp.parse(fields["totp"])
        except ValueError as exc:
            raise InvalidTotpSecret(str(exc)) from exc


class Vault:
    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path)
        self._key: bytearray | None = None  # mutable so lock() can overwrite it
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
        vault._key = bytearray(crypto.derive_key(master_password, vault._salt, vault._params))
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
        self._key, self._salt, self._params = bytearray(key), header.salt, header.params
        self._entries = entries

    def lock(self) -> None:
        """Drop the key and entries. NOTE: Python can't guarantee secure memory wiping;
        this removes our references, it does not scrub RAM. (See docs/THREAT_MODEL.md.)

        The key buffer is overwritten with zeros first. That shrinks the window, but copies made
        by the interpreter or the crypto library are out of our reach, so it is best-effort."""
        if self._key is not None:
            self._key[:] = bytes(len(self._key))
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
        atomic_write(self.path, blob)

    # ---- entries ---------------------------------------------------------------------------

    def add(self, name: str, **fields: str) -> Entry:
        self._require_unlocked()
        validate_entry_fields(name=name, **fields)
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
        validate_entry_fields(**fields)
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

    def all_entries(self) -> list[Entry]:
        self._require_unlocked()
        return [replace(self._entries[n]) for n in self.list_names()]

    def search(self, query: str) -> list[Entry]:
        """Case-insensitive match on name, username, url, notes (never password or TOTP)."""
        self._require_unlocked()
        q = query.lower()
        hits = [
            replace(e)
            for e in self._entries.values()
            if any(q in field.lower() for field in (e.name, e.username, e.url, e.notes))
        ]
        return sorted(hits, key=lambda e: e.name.lower())

    # ---- TOTP ------------------------------------------------------------------------------

    def totp_code(self, name: str, at: float | None = None) -> tuple[str, int, int]:
        """(code, seconds_remaining, period) for an entry's stored TOTP secret."""
        entry = self.get(name)
        if not entry.totp:
            raise TotpNotConfigured(f"'{name}' has no TOTP secret")
        try:
            config = totp.parse(entry.totp)
            return totp.generate(config, at), totp.seconds_remaining(config, at), config.period
        except ValueError as exc:
            raise InvalidTotpSecret(str(exc)) from exc

    # ---- import ----------------------------------------------------------------------------

    def import_entries(self, entries: list[Entry], on_conflict: str = "rename") -> ImportReport:
        """Merge entries in one atomic save. Validation happens first: all or nothing."""
        self._require_unlocked()
        if on_conflict not in CONFLICT_MODES:
            raise ValueError(f"on_conflict must be one of {CONFLICT_MODES}")
        for incoming in entries:
            validate_entry_fields(
                name=incoming.name, username=incoming.username, password=incoming.password,
                url=incoming.url, notes=incoming.notes, totp=incoming.totp,
            )
        report, now = ImportReport(), int(time.time())
        for incoming in entries:
            name = incoming.name
            if name in self._entries:
                if on_conflict == "skip":
                    report.skipped += 1
                    continue
                if on_conflict == "rename":
                    name = self._unique_name(name)
                    report.renamed += 1
                    report.added += 1
                else:
                    report.overwritten += 1
            else:
                report.added += 1
            self._entries[name] = replace(
                incoming,
                name=name,
                created=incoming.created or now,
                updated=incoming.updated or now,
            )
        if report.added or report.overwritten:
            self.save()
        return report

    def _unique_name(self, base: str) -> str:
        n = 2
        while True:
            suffix = f" ({n})"
            candidate = base[: FIELD_LIMITS["name"] - len(suffix)] + suffix
            if candidate not in self._entries:
                return candidate
            n += 1
