"""Encrypted export/import (.pmbak) and CSV import from other password managers.

There is deliberately NO plaintext export: a decrypted dump of every secret sitting in a
Downloads folder is the exact thing a password manager exists to prevent.
"""

from __future__ import annotations

import csv
import io
import json
import time
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urlparse

from . import crypto, totp
from .crypto import KdfParams
from .fileio import atomic_write
from .vault import FIELD_LIMITS, MIN_MASTER_LENGTH, Entry, VaultError, validate_entry_fields

EXPORT_FORMAT = "passwordmanager-export"
EXPORT_VERSION = 1
MAX_EXPORT_BYTES = 50 * 1024 * 1024
MAX_CSV_BYTES = 10 * 1024 * 1024
MAX_CSV_ROWS = 100_000

_TEXT_FIELDS = ("name", "username", "password", "url", "notes", "totp")
_COLUMNS = {
    "name": ("name", "title"),
    "url": ("url", "login_uri", "website", "login_url"),
    "username": ("username", "login_username"),
    "password": ("password", "login_password"),
    "notes": ("note", "notes", "extra"),
    "totp": ("login_totp", "totp", "otpauth"),
}


class PortabilityError(VaultError):
    """Export/import failed (bad file, wrong password, unsupported format)."""


def _read_limited(path: Path, limit: int) -> bytes:
    try:
        if path.stat().st_size > limit:
            raise PortabilityError(f"{path.name} is larger than the {limit // 2**20} MiB limit")
        return path.read_bytes()
    except FileNotFoundError:
        raise PortabilityError(f"file not found: {path}") from None
    except OSError as exc:
        raise PortabilityError(f"cannot read {path}: {exc.strerror or exc}") from exc


# ---- encrypted export ----------------------------------------------------------------------


def export_encrypted(
    path: str | Path,
    entries: list[Entry],
    password: str,
    params: KdfParams | None = None,
    overwrite: bool = False,
) -> int:
    if len(password) < MIN_MASTER_LENGTH:
        raise PortabilityError(f"export password must be at least {MIN_MASTER_LENGTH} characters")
    target = Path(path)
    if target.exists() and not overwrite:
        raise PortabilityError(f"{target} already exists (use --force to overwrite)")
    params = params or KdfParams()
    salt = crypto.new_salt()
    key = crypto.derive_key(password, salt, params)
    payload = json.dumps(
        {
            "format": EXPORT_FORMAT,
            "version": EXPORT_VERSION,
            "exported": int(time.time()),
            "entries": [asdict(e) for e in entries],
        }
    )
    blob = crypto.encrypt(key, payload.encode("utf-8"), salt, params, magic=crypto.EXPORT_MAGIC)
    try:
        atomic_write(target, blob, make_parents=False)
    except OSError as exc:
        raise PortabilityError(f"cannot write {target}: {exc.strerror or exc}") from exc
    return len(entries)


def _entries_from_payload(plaintext: bytes) -> list[Entry]:
    try:
        data = json.loads(plaintext)
        if data["format"] != EXPORT_FORMAT:
            raise PortabilityError("not a PasswordManager export")
        if data["version"] != EXPORT_VERSION:
            raise PortabilityError(f"unsupported export version {data['version']}")
        raw_entries = data["entries"]
        if not isinstance(raw_entries, list):
            raise TypeError
    except (ValueError, KeyError, TypeError) as exc:
        raise PortabilityError("export payload is malformed") from exc

    entries = []
    for raw in raw_entries:
        if not isinstance(raw, dict) or not isinstance(raw.get("name"), str):
            raise PortabilityError("export contains a malformed entry")
        kwargs: dict = {}
        for key in _TEXT_FIELDS:
            value = raw.get(key, "")
            if not isinstance(value, str):
                raise PortabilityError(f"export entry has a non-text '{key}'")
            kwargs[key] = value
        for key in ("created", "updated"):
            value = raw.get(key, 0)
            if not isinstance(value, int) or isinstance(value, bool):
                raise PortabilityError(f"export entry has a non-numeric '{key}'")
            kwargs[key] = value
        entries.append(Entry(**kwargs))
    return entries


def import_encrypted(path: str | Path, password: str) -> list[Entry]:
    blob = _read_limited(Path(path), MAX_EXPORT_BYTES)
    try:
        plaintext, _, _ = crypto.decrypt(password, blob, magic=crypto.EXPORT_MAGIC)
    except crypto.DecryptionError as exc:
        raise PortabilityError("wrong export password, or the file was tampered with") from exc
    except crypto.InvalidFormat as exc:
        raise PortabilityError(str(exc)) from exc
    return _entries_from_payload(plaintext)


# ---- CSV import (Chrome/Edge, Firefox, Bitwarden, 1Password, ...) --------------------------


def _hostname(url: str) -> str:
    try:
        return urlparse(url if "://" in url else f"//{url}").hostname or ""
    except ValueError:
        return ""


def parse_csv(text: str) -> tuple[list[Entry], list[str]]:
    """Returns (entries, warnings). Column names are matched case-insensitively."""
    reader = csv.DictReader(io.StringIO(text))
    try:
        header = [(h or "").strip().lower() for h in (reader.fieldnames or [])]
    except csv.Error as exc:
        raise PortabilityError(f"not a valid CSV file: {exc}") from exc
    if not header:
        raise PortabilityError("the CSV file is empty")
    reader.fieldnames = header
    column = {
        field: next((c for c in candidates if c in header), None)
        for field, candidates in _COLUMNS.items()
    }
    if not (column["password"] or column["url"] or column["name"]):
        raise PortabilityError("this CSV doesn't look like a password export (no known columns)")

    entries: list[Entry] = []
    warnings: list[str] = []
    empty = 0

    def cell(row: dict, field: str) -> str:
        col = column[field]
        value = row.get(col) if col else ""
        return value.strip() if isinstance(value, str) else ""

    try:
        for lineno, row in enumerate(reader, start=2):
            if lineno - 1 > MAX_CSV_ROWS:
                warnings.append(f"stopped after {MAX_CSV_ROWS} rows")
                break
            values = {f: cell(row, f) for f in _COLUMNS}
            if not any(values[f] for f in ("username", "password", "notes", "totp")):
                empty += 1
                continue
            clean_name = " ".join(values["name"].split())  # line breaks/tabs -> single spaces
            name = clean_name or _hostname(values["url"]) or f"imported-{lineno}"
            if values["totp"]:
                try:
                    totp.parse(values["totp"])
                except ValueError:
                    warnings.append(f"row {lineno}: ignored an invalid TOTP secret")
                    values["totp"] = ""
            try:
                validate_entry_fields(name=name, **{k: v for k, v in values.items() if k != "name"})
            except VaultError as exc:
                warnings.append(f"row {lineno} skipped: {exc}")
                continue
            entries.append(Entry(name=name, **{k: v for k, v in values.items() if k != "name"}))
    except csv.Error as exc:
        raise PortabilityError(f"not a valid CSV file: {exc}") from exc
    if empty:
        warnings.append(f"{empty} empty row(s) ignored")
    return entries, warnings


def load_import(
    path: str | Path, ask_password: Callable[[], str]
) -> tuple[list[Entry], list[str], str]:
    """Detect the file type. Returns (entries, warnings, kind) with kind 'pmbak' or 'csv'.
    `ask_password` is only called for encrypted exports."""
    target = Path(path)
    if target.is_file():
        with target.open("rb") as fh:
            head = fh.read(4)
        if head == crypto.EXPORT_MAGIC:
            return import_encrypted(target, ask_password()), [], "pmbak"
    data = _read_limited(target, MAX_CSV_BYTES)
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise PortabilityError("file is neither a PasswordManager export nor UTF-8 CSV") from exc
    entries, warnings = parse_csv(text)
    return entries, warnings, "csv"


__all__ = [
    "FIELD_LIMITS", "PortabilityError", "export_encrypted", "import_encrypted",
    "load_import", "parse_csv",
]
