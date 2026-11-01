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
