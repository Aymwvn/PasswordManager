import getpass

from passwordmanager.cli import main as cli
from passwordmanager.core.crypto import KdfParams
from passwordmanager.core.vault import Vault

MASTER = "correct horse battery"


def test_gen_command(capsys):
    assert cli.main(["gen", "-l", "24"]) == 0
    assert len(capsys.readouterr().out.strip()) == 24


def test_add_get_roundtrip(tmp_path, monkeypatch, capsys):
    path = tmp_path / "v.bin"
    Vault.create(path, MASTER, KdfParams(1, 8, 1))
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": MASTER)

    assert cli.main(["--vault", str(path), "add", "site", "-u", "me", "-g"]) == 0
    assert cli.main(["--vault", str(path), "get", "site", "--show"]) == 0
    out = capsys.readouterr().out
    assert "Username: me" in out and "Password: " in out


def test_wrong_password_exit_code(tmp_path, monkeypatch, capsys):
    path = tmp_path / "v.bin"
    Vault.create(path, MASTER, KdfParams(1, 8, 1))
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "wrong wrong wrong")
    assert cli.main(["--vault", str(path), "list"]) == 1
    assert "error:" in capsys.readouterr().err


# ---- Phase 4 commands ------------------------------------------------------------------------

import re  # noqa: E402

import pytest  # noqa: E402

from passwordmanager import __version__  # noqa: E402
from passwordmanager.core.breach import BreachCheckError  # noqa: E402

RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
EXPORT_PW = "export password 123"
FAST = KdfParams(1, 8, 1)


def answers(monkeypatch, by_prompt=None):
    """Fake getpass: answer by a fragment of the prompt text, master password by default."""
    by_prompt = by_prompt or {}

    def fake(prompt=""):
        for fragment, value in by_prompt.items():
            if fragment in prompt:
                return value
        return MASTER

    monkeypatch.setattr(getpass, "getpass", fake)


@pytest.fixture
def vpath(tmp_path):
    path = tmp_path / "v.bin"
    Vault.create(path, MASTER, FAST)
    return str(path)


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0 and __version__ in capsys.readouterr().out


def test_add_with_totp_then_show_the_code(vpath, monkeypatch, capsys):
    answers(monkeypatch, {"TOTP secret": RFC_SECRET})
    assert cli.main(["--vault", vpath, "add", "site", "-g", "--totp"]) == 0
    assert cli.main(["--vault", vpath, "totp", "site"]) == 0
    assert re.search(r"\d{3} \d{3}   \(valid for \d+s\)", capsys.readouterr().out)


def test_totp_errors(vpath, monkeypatch, capsys):
    answers(monkeypatch, {"TOTP secret": "not base32!!"})
    assert cli.main(["--vault", vpath, "add", "bad", "-g", "--totp"]) == 1
    answers(monkeypatch)
    cli.main(["--vault", vpath, "add", "plain", "-g"])
    assert cli.main(["--vault", vpath, "totp", "plain"]) == 1
    assert "no TOTP" in capsys.readouterr().err


def _seed(vpath):
    vault = Vault(vpath)
    vault.unlock(MASTER)
    vault.add("github", password="q7#Lm9!vXz2@Rw5$")
    vault.add("gitlab", password="q7#Lm9!vXz2@Rw5$")
    vault.add("forum", password="password1")
    vault.add("ok", password="Zr4&tN8*kP1^wQ6!")
    return vault


def test_audit_reports_reuse_and_weakness_without_printing_passwords(vpath, monkeypatch, capsys):
    _seed(vpath)
    answers(monkeypatch)
    assert cli.main(["--vault", vpath, "audit"]) == 0
    out = capsys.readouterr().out
    assert "github, gitlab" in out and "forum" in out and "ok" not in out.split("Weak")[1]
    assert "q7#Lm9" not in out and "password1" not in out


def test_audit_breach_check_is_opt_in_and_confirmed(vpath, monkeypatch, capsys):
    _seed(vpath)
    answers(monkeypatch)
    calls = []
    monkeypatch.setattr(cli, "check_password", lambda pw: calls.append(pw) or (9 if pw == "password1" else 0))
    monkeypatch.setattr(cli.time, "sleep", lambda _s: None)

    cli.main(["--vault", vpath, "audit"])
    assert calls == []  # no network without --breach

    monkeypatch.setattr("builtins.input", lambda _p="": "n")
    cli.main(["--vault", vpath, "audit", "--breach"])
    assert calls == [] and "Skipped" in capsys.readouterr().out  # declined the prompt

    assert cli.main(["--vault", vpath, "audit", "--breach", "-y"]) == 0
    assert "forum: seen 9 times" in capsys.readouterr().out and len(calls) == 4


def test_audit_stops_cleanly_when_offline(vpath, monkeypatch, capsys):
    _seed(vpath)
    answers(monkeypatch)

    def offline(_pw):
        raise BreachCheckError("could not reach the breach-check service")

    monkeypatch.setattr(cli, "check_password", offline)
    assert cli.main(["--vault", vpath, "audit", "--breach", "-y"]) == 1
    assert "could not reach" in capsys.readouterr().err


def test_export_then_import_into_another_vault(vpath, tmp_path, monkeypatch, capsys):
    source = Vault(vpath)
    source.unlock(MASTER)
    source.add("github", username="aymen", password="Pa55w0rd!", totp=RFC_SECRET)
    source.add("bank", password="x" * 12)
    out = tmp_path / "backup.pmbak"

    answers(monkeypatch, {"Export password": EXPORT_PW, "Confirm": EXPORT_PW})
    assert cli.main(["--vault", vpath, "export", str(out)]) == 0
    assert cli.main(["--vault", vpath, "export", str(out)]) == 1  # refuses to overwrite
    assert "already exists" in capsys.readouterr().err

    dest = tmp_path / "dest.bin"
    Vault.create(dest, MASTER, FAST)
    answers(monkeypatch, {"Export file password": EXPORT_PW})
    assert cli.main(["--vault", str(dest), "import", str(out)]) == 0
    assert "2 added" in capsys.readouterr().out
    check = Vault(dest)
    check.unlock(MASTER)
    assert check.get("github").totp == RFC_SECRET and check.get("bank").password == "x" * 12


def test_export_with_mismatched_confirmation_writes_nothing(vpath, tmp_path, monkeypatch):
    out = tmp_path / "backup.pmbak"
    state = iter([MASTER, EXPORT_PW, "something else entirely"])
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(state))
    assert cli.main(["--vault", vpath, "export", str(out)]) == 1
    assert not out.exists()


def test_csv_import_warns_about_plaintext_and_handles_conflicts(vpath, tmp_path, monkeypatch, capsys):
    csv_path = tmp_path / "chrome.csv"
    csv_path.write_text("name,url,username,password,note\nsite,https://x.com,me,pw1234567890,\n")
    answers(monkeypatch)
    assert cli.main(["--vault", vpath, "import", str(csv_path)]) == 0
    out = capsys.readouterr().out
    assert "1 added" in out and "plain text" in out
    assert cli.main(["--vault", vpath, "import", str(csv_path), "--on-conflict", "skip"]) == 0
    assert "1 skipped" in capsys.readouterr().out
    assert cli.main(["--vault", vpath, "import", str(csv_path)]) == 0  # default: rename
    assert "1 renamed" in capsys.readouterr().out


def test_import_of_a_missing_file_is_a_clean_error(vpath, tmp_path, monkeypatch, capsys):
    answers(monkeypatch)
    assert cli.main(["--vault", vpath, "import", str(tmp_path / "nope.csv")]) == 1
    assert "not found" in capsys.readouterr().err


# ---- Phase 4b: native clipboard in the CLI --------------------------------------------------------

from .conftest import FakeClipboard  # noqa: E402


def _entry_with_totp(vpath, monkeypatch):
    answers(monkeypatch, {"TOTP secret": RFC_SECRET})
    assert cli.main(["--vault", vpath, "add", "site", "-g", "--totp"]) == 0
    answers(monkeypatch)


def test_totp_copy_uses_the_native_clipboard_and_clears_it(vpath, monkeypatch, capsys):
    fake = FakeClipboard()
    monkeypatch.setattr(cli, "default_backend", lambda: fake)
    monkeypatch.setattr(cli.time, "sleep", lambda _s: None)
    _entry_with_totp(vpath, monkeypatch)
    assert cli.main(["--vault", vpath, "totp", "site", "--copy"]) == 0
    assert len(fake.copied) == 1 and re.fullmatch(r"\d{6}", fake.copied[0])
    assert fake.text == ""  # still ours after the wait, so it was cleared


def test_cli_leaves_alone_what_the_user_copied_during_the_wait(vpath, monkeypatch):
    fake = FakeClipboard()
    monkeypatch.setattr(cli, "default_backend", lambda: fake)
    monkeypatch.setattr(cli.time, "sleep", lambda _s: fake.user_copies("something else"))
    _entry_with_totp(vpath, monkeypatch)
    cli.main(["--vault", vpath, "totp", "site", "--copy"])
    assert fake.text == "something else"
