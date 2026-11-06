import os

import pytest

from passwordmanager.core import crypto
from passwordmanager.core.vault import (
    EntryExists,
    EntryNotFound,
    InvalidPassword,
    Vault,
    VaultCorrupted,
    VaultExists,
    VaultLocked,
    VaultNotFound,
    WeakMasterPassword,
)

from .conftest import MASTER


def test_create_and_unlock(vault, vault_path):
    vault.add("github", username="aymen", password="hunter2hunter2")
    fresh = Vault(vault_path)
    fresh.unlock(MASTER)
    entry = fresh.get("github")
    assert (entry.username, entry.password) == ("aymen", "hunter2hunter2")


def test_wrong_master_password(vault, vault_path):
    with pytest.raises(InvalidPassword):
        Vault(vault_path).unlock("totally wrong password")


def test_weak_master_rejected(vault_path, fast_params):
    with pytest.raises(WeakMasterPassword):
        Vault.create(vault_path, "short", fast_params)


def test_create_refuses_to_overwrite(vault, vault_path, fast_params):
    with pytest.raises(VaultExists):
        Vault.create(vault_path, MASTER, fast_params)


def test_missing_vault(tmp_path):
    with pytest.raises(VaultNotFound):
        Vault(tmp_path / "nope.bin").unlock(MASTER)


def test_not_a_vault_file(tmp_path):
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"this is definitely not a vault, just some text" * 3)
    with pytest.raises(VaultCorrupted):
        Vault(junk).unlock(MASTER)


def test_nothing_readable_on_disk(vault, vault_path):
    vault.add("my-bank-login", username="alice", password="SuperSecret123!")
    raw = vault_path.read_bytes()
    for needle in (b"SuperSecret123!", b"my-bank-login", b"alice"):
        assert needle not in raw


def test_tampered_vault_file_rejected(vault, vault_path):
    vault.add("x", password="y")
    raw = bytearray(vault_path.read_bytes())
    raw[-5] ^= 0xFF
    vault_path.write_bytes(bytes(raw))
    with pytest.raises(InvalidPassword):
        Vault(vault_path).unlock(MASTER)


def test_new_nonce_on_every_save(vault, vault_path):
    def nonce():
        return crypto.parse_header(vault_path.read_bytes()).nonce

    first = nonce()
    vault.add("a", password="1")
    second = nonce()
    vault.add("b", password="2")
    assert len({first, second, nonce()}) == 3


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions only")
def test_vault_file_permissions(vault, vault_path):
    assert oct(vault_path.stat().st_mode & 0o777) == "0o600"


def test_crud(vault):
    vault.add("site", username="u", password="p1", url="https://example.com")
    with pytest.raises(EntryExists):
        vault.add("site")
    vault.update("site", password="p2")
    assert vault.get("site").password == "p2"
    vault.delete("site")
    with pytest.raises(EntryNotFound):
        vault.get("site")
    with pytest.raises(EntryNotFound):
        vault.delete("site")


def test_update_rejects_unknown_fields(vault):
    vault.add("site")
    with pytest.raises(ValueError):
        vault.update("site", created=0)


def test_search_ignores_passwords(vault):
    vault.add("GitHub", username="aymen", url="https://github.com", password="findme")
    vault.add("Gmail", username="aymen@example.com", password="x")
    assert [e.name for e in vault.search("git")] == ["GitHub"]
    assert [e.name for e in vault.search("AYMEN")] == ["GitHub", "Gmail"]
    assert vault.search("findme") == []


def test_returned_entries_are_copies(vault):
    vault.add("site", password="original")
    vault.get("site").password = "mutated"
    assert vault.get("site").password == "original"


def test_locked_vault_refuses_everything(vault):
    vault.add("site", password="p")
    vault.lock()
    assert not vault.is_unlocked
    for call in (lambda: vault.get("site"), vault.list_names, vault.save,
                 lambda: vault.add("other")):
        with pytest.raises(VaultLocked):
            call()


def test_kdf_params_persist(vault, vault_path, fast_params):
    vault.add("x")
    assert crypto.parse_header(vault_path.read_bytes()).params == fast_params


# ---- TOTP, field limits, import compatibility (Phase 4) ---------------------------------------

import json  # noqa: E402

from passwordmanager.core.vault import (  # noqa: E402
    Entry,
    InvalidEntry,
    InvalidTotpSecret,
    TotpNotConfigured,
)

RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # base32 of the RFC 6238 SHA-1 test key


def test_totp_is_stored_encrypted_and_produces_codes(vault, vault_path):
    vault.add("site", password="p", totp=RFC_SECRET)
    assert RFC_SECRET.encode() not in vault_path.read_bytes()
    reloaded = Vault(vault_path)
    reloaded.unlock(MASTER)
    code, remaining, period = reloaded.totp_code("site", at=59)
    assert (code, remaining, period) == ("287082", 1, 30)


def test_invalid_totp_is_rejected_and_nothing_is_saved(vault):
    with pytest.raises(InvalidTotpSecret):
        vault.add("site", totp="definitely not base32!!")
    assert vault.list_names() == []
    vault.add("site")
    with pytest.raises(InvalidTotpSecret):
        vault.update("site", totp="otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP")
    assert vault.get("site").totp == ""


def test_totp_can_be_removed_and_missing_totp_is_reported(vault):
    vault.add("site", totp=RFC_SECRET)
    vault.update("site", totp="")
    with pytest.raises(TotpNotConfigured):
        vault.totp_code("site")


def test_search_never_matches_secrets(vault):
    vault.add("site", password="needle-pw", totp=RFC_SECRET)
    assert vault.search("needle") == [] and vault.search("GEZDGNBV") == []


def test_field_limits_are_enforced_on_every_write_path(vault):
    with pytest.raises(InvalidEntry):
        vault.add("")
    with pytest.raises(InvalidEntry):
        vault.add("x", username="u" * 501)
    vault.add("x")
    with pytest.raises(InvalidEntry):
        vault.update("x", notes="n" * 10_001)


def test_vaults_written_before_totp_existed_still_open(vault_path, fast_params):
    salt = crypto.new_salt()
    key = crypto.derive_key(MASTER, salt, fast_params)
    old_payload = {"entries": {"old": {"name": "old", "username": "u", "password": "p",
                                       "url": "", "notes": "", "created": 1, "updated": 2}}}
    vault_path.write_bytes(crypto.encrypt(key, json.dumps(old_payload).encode(), salt, fast_params))
    reopened = Vault(vault_path)
    reopened.unlock(MASTER)
    assert reopened.get("old").totp == "" and reopened.get("old").password == "p"


@pytest.mark.parametrize("name", ["a\nb", "\n", "tab\there", "nul\x00", "cr\rlf"])
def test_names_with_control_characters_are_rejected(vault, name):  # F-E
    with pytest.raises(InvalidEntry):
        vault.add(name)
    with pytest.raises(InvalidEntry):
        vault.import_entries([Entry(name)])
    assert vault.list_names() == []
