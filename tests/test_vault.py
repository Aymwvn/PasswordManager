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
