"""Command-line interface. Thin wrapper over passwordmanager.core."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import time
from pathlib import Path

from passwordmanager.core.generator import estimate_entropy_bits, generate_password, strength_label
from passwordmanager.core.vault import Entry, Vault, VaultError

CLIP_SECONDS = 15


def _vault_path(args: argparse.Namespace) -> Path:
    if args.vault:
        return Path(args.vault)
    env = os.environ.get("PM_VAULT")
    return Path(env) if env else Path.home() / ".passwordmanager" / "vault.bin"


def _open(args: argparse.Namespace) -> Vault:
    vault = Vault(_vault_path(args))
    vault.unlock(getpass.getpass("Master password: "))
    return vault


def _copy_temporarily(secret: str) -> bool:
    try:
        import pyperclip
    except ImportError:
        return False
    pyperclip.copy(secret)
    print(f"Password copied. Clearing clipboard in {CLIP_SECONDS}s (Ctrl+C to clear now)...")
    try:
        time.sleep(CLIP_SECONDS)
    except KeyboardInterrupt:
        pass
    finally:
        if pyperclip.paste() == secret:  # don't wipe something the user copied since
            pyperclip.copy("")
    return True


def _print_entry(entry: Entry, show_password: bool) -> None:
    print(f"Name:     {entry.name}")
    if entry.username:
        print(f"Username: {entry.username}")
    if entry.url:
        print(f"URL:      {entry.url}")
    if entry.notes:
        print(f"Notes:    {entry.notes}")
    if show_password:
        print(f"Password: {entry.password}")


def _resolve_password(args: argparse.Namespace, prompt: bool = True) -> str | None:
    if args.generate:
        return generate_password(args.length, symbols=not args.no_symbols)
    if prompt:
        return getpass.getpass("Entry password: ")
    return None


# ---- commands ------------------------------------------------------------------------------


def cmd_init(args: argparse.Namespace) -> int:
    pw = getpass.getpass("New master password (12+ chars, a passphrase is best): ")
    if pw != getpass.getpass("Confirm: "):
        print("error: passwords don't match", file=sys.stderr)
        return 1
    vault = Vault.create(_vault_path(args), pw)
    print(f"Vault created at {vault.path}")
    return 0


def cmd_add(args: argparse.Namespace) -> int:
    vault = _open(args)
    password = _resolve_password(args)
    vault.add(args.name, username=args.user, password=password, url=args.url, notes=args.notes)
    if args.generate:
        bits = estimate_entropy_bits(password)
        print(f"Saved '{args.name}' with a generated password (~{bits:.0f} bits, "
              f"{strength_label(bits)}).")
    else:
        print(f"Saved '{args.name}'.")
    return 0


def cmd_get(args: argparse.Namespace) -> int:
    entry = _open(args).get(args.name)
    _print_entry(entry, show_password=args.show)
    if not args.show and not _copy_temporarily(entry.password):
        print("(install pyperclip for clipboard support, or use --show)")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    for name in _open(args).list_names():
        print(f"- {name}")
    return 0


def cmd_search(args: argparse.Namespace) -> int:
    hits = _open(args).search(args.query)
    if not hits:
        print("No matches.")
    for entry in hits:
        print(f"- {entry.name}  ({entry.username or 'no username'})  {entry.url}")
    return 0


def cmd_edit(args: argparse.Namespace) -> int:
    vault = _open(args)
    changes: dict[str, str] = {}
    if args.user is not None:
        changes["username"] = args.user
    if args.url is not None:
        changes["url"] = args.url
    if args.notes is not None:
        changes["notes"] = args.notes
    if args.generate:
        changes["password"] = generate_password(args.length, symbols=not args.no_symbols)
    elif args.password:
        changes["password"] = getpass.getpass("New entry password: ")
    if not changes:
        print("Nothing to change. Use -u, --url, --notes, -p or -g.", file=sys.stderr)
        return 1
    vault.update(args.name, **changes)
    print(f"Updated '{args.name}' ({', '.join(changes)}).")
    return 0


def cmd_delete(args: argparse.Namespace) -> int:
    vault = _open(args)
    if not args.yes and input(f"Delete '{args.name}'? [y/N] ").strip().lower() != "y":
        print("Cancelled.")
        return 1
    vault.delete(args.name)
    print("Deleted.")
    return 0


def cmd_gen(args: argparse.Namespace) -> int:
    pw = generate_password(args.length, symbols=not args.no_symbols)
    print(pw)
    return 0


# ---- argument parsing ----------------------------------------------------------------------


def _add_gen_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("-g", "--generate", action="store_true", help="generate a random password")
    p.add_argument("-l", "--length", type=int, default=20, help="generated length (default 20)")
    p.add_argument("--no-symbols", action="store_true", help="letters and digits only")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pm", description="PasswordManager - local encrypted vault")
    p.add_argument("--vault", help="vault file path (default: ~/.passwordmanager/vault.bin)")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create a new vault").set_defaults(func=cmd_init)

    s = sub.add_parser("add", help="add an entry")
    s.add_argument("name")
    s.add_argument("-u", "--user", default="")
    s.add_argument("--url", default="")
    s.add_argument("--notes", default="")
    _add_gen_flags(s)
    s.set_defaults(func=cmd_add)

    s = sub.add_parser("get", help="show an entry and copy its password")
    s.add_argument("name")
    s.add_argument("--show", action="store_true", help="print the password instead of copying")
    s.set_defaults(func=cmd_get)

    sub.add_parser("list", help="list entry names").set_defaults(func=cmd_list)

    s = sub.add_parser("search", help="search name/username/url/notes")
    s.add_argument("query")
    s.set_defaults(func=cmd_search)

    s = sub.add_parser("edit", help="edit an entry")
    s.add_argument("name")
    s.add_argument("-u", "--user")
    s.add_argument("--url")
    s.add_argument("--notes")
    s.add_argument("-p", "--password", action="store_true", help="prompt for a new password")
    _add_gen_flags(s)
    s.set_defaults(func=cmd_edit)

    s = sub.add_parser("delete", help="delete an entry")
    s.add_argument("name")
    s.add_argument("-y", "--yes", action="store_true")
    s.set_defaults(func=cmd_delete)

    s = sub.add_parser("gen", help="generate a password (no vault needed)")
    s.add_argument("-l", "--length", type=int, default=20)
    s.add_argument("--no-symbols", action="store_true")
    s.set_defaults(func=cmd_gen)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except VaultError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
