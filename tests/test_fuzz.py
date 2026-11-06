"""Property-based fuzzing: hostile vault files and hostile HTTP input must fail *safely*.

Safe = a clean VaultError / 4xx, never an unhandled exception or a 5xx, and a modified vault
must never decrypt. Hypothesis shrinks any failure to a minimal reproducer.
"""

import os
import tempfile
from pathlib import Path
from urllib.parse import quote

import pytest

pytest.importorskip("hypothesis")
pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402
from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from passwordmanager.core import crypto  # noqa: E402
from passwordmanager.core.crypto import KdfParams  # noqa: E402
from passwordmanager.core.vault import Vault, VaultError  # noqa: E402
from passwordmanager.ui.server import create_app  # noqa: E402

FAST = KdfParams(1, 8, 1)
MASTER = "correct horse battery"
EXAMPLES = int(os.environ.get("PM_FUZZ_EXAMPLES", "60"))  # PM_FUZZ_EXAMPLES=1000 for a deep run
FUZZ = settings(max_examples=EXAMPLES, deadline=None, suppress_health_check=list(HealthCheck))


def _valid_blob() -> bytes:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "v.bin"
        vault = Vault.create(path, MASTER, FAST)
        for i in range(3):
            vault.add(f"entry{i}", username="u", password="p" * 20, notes="n")
        return path.read_bytes()


BLOB = _valid_blob()
# Bytes 5..16 hold the KDF parameters. Flipping them is covered deterministically below
# (random flips there could request large Argon2 allocations and just slow the fuzzer down).
MUTABLE = [i for i in range(len(BLOB)) if not 5 <= i <= 16]


def _unlock_bytes(data: bytes) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "v.bin"
        path.write_bytes(data)
        Vault(path).unlock(MASTER)


# ---- hostile vault files ---------------------------------------------------------------------


def test_baseline_blob_unlocks():
    _unlock_bytes(BLOB)


@FUZZ
@given(st.binary(max_size=300))
def test_random_bytes_never_crash_unlock(data):
    with pytest.raises(VaultError):
        _unlock_bytes(data)


@FUZZ
@given(
    time_cost=st.integers(0, 12),
    memory=st.integers(0, 600),
    parallelism=st.integers(0, 20),
    salt=st.binary(min_size=16, max_size=16),
    nonce=st.binary(min_size=12, max_size=12),
    ciphertext=st.binary(min_size=16, max_size=64),
)
def test_well_formed_header_with_any_kdf_params_fails_safely(
    time_cost, memory, parallelism, salt, nonce, ciphertext
):
    header = crypto._HEADER.pack(
        crypto.MAGIC, crypto.FORMAT_VERSION, time_cost, memory, parallelism, salt, nonce
    )
    with pytest.raises(VaultError):
        _unlock_bytes(header + ciphertext)


@FUZZ
@given(index=st.sampled_from(MUTABLE), flip=st.integers(1, 255))
def test_any_single_byte_change_is_detected(index, flip):
    data = bytearray(BLOB)
    data[index] ^= flip
    with pytest.raises(VaultError):
        _unlock_bytes(bytes(data))


@FUZZ
@given(st.integers(0, len(BLOB) - 1))
def test_any_truncation_is_rejected(length):
    with pytest.raises(VaultError):
        _unlock_bytes(BLOB[:length])


@pytest.mark.parametrize("offset,new_value", [(5, 2), (9, 16), (13, 2)])
def test_kdf_field_tampering_is_detected(offset, new_value):
    data = bytearray(BLOB)
    data[offset : offset + 4] = new_value.to_bytes(4, "big")
    with pytest.raises(VaultError):
        _unlock_bytes(bytes(data))


# ---- hostile HTTP input ----------------------------------------------------------------------


def _session(tmp):
    app = create_app(
        Path(tmp) / "v.bin",
        allowed_hosts={"testserver"},
        auto_lock_seconds=3600,
        kdf_params=FAST,
    )
    client = TestClient(app)
    token = client.post("/api/init", json={"master_password": MASTER}).json()["csrf_token"]
    client.headers["X-CSRF-Token"] = token
    return app, client


short_text = st.text(max_size=40)


@FUZZ
@given(name=st.text(st.characters(blacklist_categories=("Cs", "Cc")), min_size=1, max_size=40),
       username=short_text, password=short_text, url=short_text, notes=short_text)
def test_entries_roundtrip_any_unicode(name, username, password, url, notes):
    entry = {"name": name, "username": username, "password": password, "url": url, "notes": notes}
    with tempfile.TemporaryDirectory() as tmp:
        _, client = _session(tmp)
        assert client.post("/api/entries", json=entry).status_code == 201
        path = "/api/entries/" + quote(name, safe="")
        got = client.get(path).json()
        assert {k: got[k] for k in entry} == entry
        assert [e["name"] for e in client.get("/api/entries").json()] == [name]
        assert client.delete(path).status_code == 200


json_values = st.recursive(
    st.none()
    | st.booleans()
    | st.integers(-(2**40), 2**40)
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text(max_size=20),
    lambda kids: (
        st.lists(kids, max_size=3) | st.dictionaries(st.text(max_size=12), kids, max_size=4)
    ),
    max_leaves=12,
)


@FUZZ
@given(body=json_values)
def test_random_json_bodies_never_cause_5xx(body):
    with tempfile.TemporaryDirectory() as tmp:
        _, client = _session(tmp)
        for method, path in [("post", "/api/entries"), ("put", "/api/entries/x"),
                             ("post", "/api/unlock"), ("post", "/api/init")]:
            assert getattr(client, method)(path, json=body).status_code < 500


@FUZZ
@given(q=st.text(max_size=300), name=st.text(max_size=60))
def test_random_paths_and_queries_never_cause_5xx(q, name):
    with tempfile.TemporaryDirectory() as tmp:
        _, client = _session(tmp)
        encoded = quote(name, safe="")
        assert client.get("/api/entries", params={"q": q}).status_code < 500
        assert client.get("/api/generate", params={"length": q}).status_code < 500
        for method in ("get", "put", "delete"):
            kwargs = {"json": {"url": "x"}} if method == "put" else {}
            assert getattr(client, method)(f"/api/entries/{encoded}", **kwargs).status_code < 500


@FUZZ
@given(host=st.from_regex(r"[a-zA-Z0-9.:\[\]-]{0,40}", fullmatch=True))
def test_unknown_host_headers_are_always_rejected(host):
    with tempfile.TemporaryDirectory() as tmp:
        app = create_app(Path(tmp) / "v.bin", allowed_hosts={"testserver"}, kdf_params=FAST)
        res = TestClient(app).get("/api/status", headers={"host": host})
        assert res.status_code == (200 if host == "testserver" else 400)


@FUZZ
@given(cookie=st.from_regex(r"[A-Za-z0-9_\-]{0,80}", fullmatch=True))
def test_random_session_cookies_never_authenticate(cookie):
    with tempfile.TemporaryDirectory() as tmp:
        app, _ = _session(tmp)  # a live, unlocked session exists
        attacker = TestClient(app, headers={"cookie": f"pm_session={cookie}"})
        assert attacker.get("/api/entries").status_code == 401


@FUZZ
@given(token=st.from_regex(r"[A-Za-z0-9_\-]{0,80}", fullmatch=True))
def test_random_csrf_tokens_never_pass(token):
    with tempfile.TemporaryDirectory() as tmp:
        _, client = _session(tmp)  # valid cookie, but we override the CSRF header
        res = client.post("/api/entries", json={"name": "x"}, headers={"X-CSRF-Token": token})
        assert res.status_code == 403


# ---- Phase 4 parsers: encrypted exports and CSV imports ---------------------------------------

import csv  # noqa: E402
import io  # noqa: E402

from passwordmanager.core.portability import (  # noqa: E402
    export_encrypted,
    import_encrypted,
    parse_csv,
)
from passwordmanager.core.vault import Entry, validate_entry_fields  # noqa: E402

EXPORT_PW = "export password 123"


def _valid_export() -> bytes:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "b.pmbak"
        export_encrypted(path, [Entry("a", "u", "p" * 12, "https://x", "n", "JBSWY3DPEHPK3PXP")],
                         EXPORT_PW, FAST)
        return path.read_bytes()


EXPORT_BLOB = _valid_export()
EXPORT_MUTABLE = [i for i in range(len(EXPORT_BLOB)) if not 5 <= i <= 16]


def _import_bytes(data: bytes):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "b.pmbak"
        path.write_bytes(data)
        return import_encrypted(path, EXPORT_PW)


def test_baseline_export_imports():
    assert _import_bytes(EXPORT_BLOB)[0].name == "a"


@FUZZ
@given(st.binary(max_size=400))
def test_random_bytes_never_crash_the_export_importer(data):
    with pytest.raises(VaultError):
        _import_bytes(data)


@FUZZ
@given(index=st.sampled_from(EXPORT_MUTABLE), flip=st.integers(1, 255))
def test_any_single_byte_change_in_an_export_is_detected(index, flip):
    data = bytearray(EXPORT_BLOB)
    data[index] ^= flip
    with pytest.raises(VaultError):
        _import_bytes(bytes(data))


@FUZZ
@given(st.integers(0, len(EXPORT_BLOB) - 1))
def test_any_truncation_of_an_export_is_rejected(length):
    with pytest.raises(VaultError):
        _import_bytes(EXPORT_BLOB[:length])


def _assert_clean(entries):
    for entry in entries:
        assert entry.name
        validate_entry_fields(
            name=entry.name, username=entry.username, password=entry.password,
            url=entry.url, notes=entry.notes, totp=entry.totp,
        )


@FUZZ
@given(st.text(max_size=600))
def test_arbitrary_text_as_csv_never_crashes_and_never_yields_bad_entries(text):
    try:
        entries, _ = parse_csv(text)
    except VaultError:
        return
    _assert_clean(entries)


cell = st.text(max_size=700)


@FUZZ
@given(rows=st.lists(st.tuples(cell, cell, cell, cell, cell, cell), max_size=8))
def test_structured_csv_with_hostile_cells_stays_within_limits(rows):
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["name", "url", "username", "password", "note", "login_totp"])
    writer.writerows(rows)
    try:
        entries, _ = parse_csv(buffer.getvalue())
    except VaultError:
        return
    _assert_clean(entries)
    assert len(entries) <= len(rows)
