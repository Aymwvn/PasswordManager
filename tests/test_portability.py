import os

import pytest

from passwordmanager.core import crypto
from passwordmanager.core import portability as pm
from passwordmanager.core.portability import (
    PortabilityError,
    export_encrypted,
    import_encrypted,
    load_import,
    parse_csv,
)
from passwordmanager.core.vault import Entry, InvalidEntry, Vault, VaultCorrupted

PW = "export password 123"


def sample():
    return [
        Entry("github", "aymen", "Pa55w0rd!", "https://github.com", "n", "JBSWY3DPEHPK3PXP", 100, 200),
        Entry("bank", password="x" * 5),
    ]


@pytest.fixture
def export_path(tmp_path):
    return tmp_path / "backup.pmbak"


# ---- encrypted export ------------------------------------------------------------------------


def test_roundtrip(export_path, fast_params):
    assert export_encrypted(export_path, sample(), PW, fast_params) == 2
    assert import_encrypted(export_path, PW) == sample()


def test_nothing_readable_in_the_export_file(export_path, fast_params):
    export_encrypted(export_path, sample(), PW, fast_params)
    raw = export_path.read_bytes()
    for needle in (b"github", b"Pa55w0rd!", b"JBSWY3DP", b"aymen", b"bank"):
        assert needle not in raw


def test_wrong_password_and_tampering_are_detected(export_path, fast_params):
    export_encrypted(export_path, sample(), PW, fast_params)
    with pytest.raises(PortabilityError):
        import_encrypted(export_path, "not the password")
    raw = bytearray(export_path.read_bytes())
    raw[-3] ^= 0x01
    export_path.write_bytes(bytes(raw))
    with pytest.raises(PortabilityError):
        import_encrypted(export_path, PW)


def test_export_refuses_to_overwrite_unless_forced(export_path, fast_params):
    export_encrypted(export_path, sample(), PW, fast_params)
    with pytest.raises(PortabilityError):
        export_encrypted(export_path, sample(), PW, fast_params)
    assert export_encrypted(export_path, sample()[:1], PW, fast_params, overwrite=True) == 1


def test_export_password_must_be_long_enough(export_path):
    with pytest.raises(PortabilityError):
        export_encrypted(export_path, sample(), "short")
    assert not export_path.exists()


def test_export_to_a_missing_directory_is_a_clean_error(tmp_path, fast_params):
    with pytest.raises(PortabilityError):
        export_encrypted(tmp_path / "nope" / "x.pmbak", sample(), PW, fast_params)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions only")
def test_export_file_is_private(export_path, fast_params):
    export_encrypted(export_path, sample(), PW, fast_params)
    assert oct(export_path.stat().st_mode & 0o777) == "0o600"


def test_vault_and_export_files_are_not_interchangeable(vault, vault_path, export_path, fast_params):
    vault.add("x", password="y")
    with pytest.raises(PortabilityError):
        import_encrypted(vault_path, "correct horse battery")
    export_encrypted(export_path, sample(), PW, fast_params)
    with pytest.raises(VaultCorrupted):
        Vault(export_path).unlock(PW)


def test_missing_and_oversized_files(tmp_path, export_path, fast_params, monkeypatch):
    with pytest.raises(PortabilityError):
        import_encrypted(tmp_path / "missing.pmbak", PW)
    export_encrypted(export_path, sample(), PW, fast_params)
    monkeypatch.setattr(pm, "MAX_EXPORT_BYTES", 10)
    with pytest.raises(PortabilityError):
        import_encrypted(export_path, PW)


def _encrypted(payload: bytes, params) -> bytes:
    salt = crypto.new_salt()
    key = crypto.derive_key(PW, salt, params)
    return crypto.encrypt(key, payload, salt, params, magic=crypto.EXPORT_MAGIC)


@pytest.mark.parametrize(
    "payload",
    [
        b"not json",
        b"[]",
        b'{"format": "something-else", "version": 1, "entries": []}',
        b'{"format": "passwordmanager-export", "version": 99, "entries": []}',
        b'{"format": "passwordmanager-export", "version": 1, "entries": {}}',
        b'{"format": "passwordmanager-export", "version": 1, "entries": [5]}',
        b'{"format": "passwordmanager-export", "version": 1, "entries": [{"name": 5}]}',
        b'{"format": "passwordmanager-export", "version": 1, "entries": [{"name": "a", "password": 1}]}',
        b'{"format": "passwordmanager-export", "version": 1, "entries": [{"name": "a", "created": true}]}',
    ],
)
def test_malformed_payloads_are_rejected(tmp_path, fast_params, payload):
    path = tmp_path / "x.pmbak"
    path.write_bytes(_encrypted(payload, fast_params))
    with pytest.raises(PortabilityError):
        import_encrypted(path, PW)


# ---- CSV import ------------------------------------------------------------------------------

CHROME = "name,url,username,password,note\ngithub.com,https://github.com/login,aymen,hunter2hunter2,my note\n"
BITWARDEN = (
    "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n"
    ",,login,GitHub,,,0,https://github.com,aymen,pw123456789,JBSWY3DPEHPK3PXP\n"
    ",,note,Wifi code,the code is 1234,,0,,,,\n"
)
FIREFOX = (
    "url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged\n"
    "https://www.example.com/login,bob,secret,,,{g},1,2,3\n"
)
ONEPASSWORD = "Title,Url,Username,Password,Notes,Type\nNetflix,https://netflix.com,me,pw,hello,Login\n"


def test_chrome_csv():
    entries, warnings = parse_csv(CHROME)
    assert entries == [Entry("github.com", "aymen", "hunter2hunter2", "https://github.com/login", "my note")]
    assert warnings == []


def test_bitwarden_csv_with_totp_and_secure_note():
    entries, _ = parse_csv(BITWARDEN)
    assert [e.name for e in entries] == ["GitHub", "Wifi code"]
    assert entries[0].totp == "JBSWY3DPEHPK3PXP" and entries[0].password == "pw123456789"
    assert entries[1].notes == "the code is 1234" and entries[1].password == ""


def test_firefox_csv_names_come_from_the_hostname():
    entries, _ = parse_csv(FIREFOX)
    assert entries[0].name == "www.example.com" and entries[0].username == "bob"


def test_onepassword_csv():
    entries, _ = parse_csv(ONEPASSWORD)
    assert (entries[0].name, entries[0].notes, entries[0].url) == ("Netflix", "hello", "https://netflix.com")


def test_invalid_totp_is_dropped_with_a_warning_not_a_failure():
    text = "name,password,login_totp\nsite,pw,not-a-secret!!\n"
    entries, warnings = parse_csv(text)
    assert entries[0].totp == "" and any("TOTP" in w for w in warnings)


def test_blank_rows_and_overlong_fields_are_reported():
    text = "name,username,password\nok,u,p\n,,\nbad," + "u" * 600 + ",p\n"
    entries, warnings = parse_csv(text)
    assert [e.name for e in entries] == ["ok"]
    assert any("skipped" in w for w in warnings) and any("empty" in w for w in warnings)


def test_spreadsheet_formulas_are_kept_as_plain_data():
    entries, _ = parse_csv("name,username,password\n=HYPERLINK(\"http://x\"),+1,@SUM(1)\n")
    assert entries[0].name == '=HYPERLINK("http://x")' and entries[0].password == "@SUM(1)"


@pytest.mark.parametrize("text", ["", "a,b,c\n1,2,3\n", "name,password\nx," + "A" * 200_000 + "\n"])
def test_unusable_csv_is_a_clean_error(text):
    with pytest.raises(PortabilityError):
        parse_csv(text)


def test_load_import_detects_the_type_and_only_asks_for_a_password_when_needed(
    tmp_path, export_path, fast_params
):
    csv_path = tmp_path / "chrome.csv"
    csv_path.write_text("\ufeff" + CHROME, encoding="utf-8")  # Excel-style BOM

    def never():
        raise AssertionError("a CSV must not prompt for a password")

    entries, _, kind = load_import(csv_path, never)
    assert kind == "csv" and entries[0].name == "github.com"

    export_encrypted(export_path, sample(), PW, fast_params)
    entries, _, kind = load_import(export_path, lambda: PW)
    assert kind == "pmbak" and entries == sample()


def test_binary_garbage_is_not_mistaken_for_csv(tmp_path):
    path = tmp_path / "junk.bin"
    path.write_bytes(b"\xff\xfe\x00\x01" * 50)
    with pytest.raises(PortabilityError):
        load_import(path, lambda: PW)


# ---- merging into a vault --------------------------------------------------------------------


def test_conflicts_rename_by_default_and_never_lose_data(vault, vault_path):
    vault.add("github", password="original")
    report = vault.import_entries([Entry("github", password="a"), Entry("github", password="b"),
                                   Entry("new", password="c")])
    assert (report.added, report.renamed, report.skipped, report.overwritten) == (3, 2, 0, 0)
    assert vault.get("github").password == "original"
    assert vault.get("github (2)").password == "a" and vault.get("github (3)").password == "b"
    reloaded = Vault(vault_path)
    reloaded.unlock("correct horse battery")
    assert reloaded.list_names() == ["github", "github (2)", "github (3)", "new"]


def test_skip_and_overwrite_modes(vault):
    vault.add("site", password="original")
    skipped = vault.import_entries([Entry("site", password="new")], on_conflict="skip")
    assert (skipped.skipped, vault.get("site").password) == (1, "original")
    over = vault.import_entries([Entry("site", password="new")], on_conflict="overwrite")
    assert (over.overwritten, vault.get("site").password) == (1, "new")
    with pytest.raises(ValueError):
        vault.import_entries([], on_conflict="bogus")


def test_import_is_all_or_nothing_on_validation(vault):
    with pytest.raises(InvalidEntry):
        vault.import_entries([Entry("fine", password="p"), Entry("x" * 201)])
    assert vault.list_names() == []


def test_rename_respects_the_name_length_limit(vault):
    long_name = "n" * 200
    vault.add(long_name)
    vault.import_entries([Entry(long_name)])
    assert all(len(name) <= 200 for name in vault.list_names()) and len(vault.list_names()) == 2


def test_timestamps_are_kept_or_filled(vault):
    vault.import_entries([Entry("old", created=100, updated=200), Entry("fresh")])
    assert (vault.get("old").created, vault.get("old").updated) == (100, 200)
    assert vault.get("fresh").created > 0


def test_csv_names_with_line_breaks_are_cleaned_not_rejected():  # F-E
    entries, _ = parse_csv('name,username,password\n"line one\nline two",u,p\n"\n",u2,p2\n')
    assert entries[0].name == "line one line two"
    assert entries[1].name.startswith("imported-")
