"""Command-line interface. Thin wrapper over passwordmanager.core."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import time
from pathlib import Path

from passwordmanager import __version__
from passwordmanager.core.audit import audit
from passwordmanager.core.breach import BreachCheckError, check_password
from passwordmanager.core.generator import estimate_entropy_bits, generate_password, strength_label
from passwordmanager.core.portability import export_encrypted, load_import
from passwordmanager.core.vault import CONFLICT_MODES, Entry, Vault, VaultError

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


def _copy_temporarily(secret: str, what: str = "Password") -> bool:
    try:
        import pyperclip
    except ImportError:
        return False
    pyperclip.copy(secret)
    print(f"{what} copied. Clearing clipboard in {CLIP_SECONDS}s (Ctrl+C to clear now)...")
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
    totp_value = getpass.getpass("TOTP secret or otpauth:// link: ").strip() if args.totp else ""
    vault.add(
        args.name, username=args.user, password=password, url=args.url, notes=args.notes,
        totp=totp_value,
    )
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
    if args.totp:
        changes["totp"] = getpass.getpass("TOTP secret or link (empty removes it): ").strip()
    if not changes:
        print("Nothing to change. Use -u, --url, --notes, -p, -g or --totp.", file=sys.stderr)
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


def cmd_totp(args: argparse.Namespace) -> int:
    code, remaining, _ = _open(args).totp_code(args.name)
    half = len(code) // 2
    print(f"{code[:half]} {code[half:]}   (valid for {remaining}s)")
    if args.copy and not _copy_temporarily(code, "Code"):
        print("(install pyperclip for clipboard support)")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    entries = _open(args).all_entries()
    report = audit(entries)
    print(f"Checked {len(entries)} entries.")
    if report.reused:
        print("\nReused passwords (give each its own):")
        for names in report.reused:
            print("  - " + ", ".join(names))
    if report.weak:
        print("\nWeak passwords (short or low estimated entropy):")
        for name, bits in report.weak:
            print(f"  - {name} (~{bits} bits)")
    if report.no_password:
        print(f"\nNo password stored: {', '.join(report.no_password)}")
    if not report.has_issues:
        print("No reused or weak passwords found.")
    if not args.breach:
        print("\nTip: add --breach to also check Have I Been Pwned.")
        return 0
    prompt = ("\nThis sends only a 5-character SHA-1 prefix per password to "
              "api.pwnedpasswords.com. Continue? [y/N] ")
    if not args.yes and input(prompt).strip().lower() != "y":
        print("Skipped the breach check.")
        return 0
    print("\nBreach check (Have I Been Pwned):")
    found = 0
    for entry in entries:
        if not entry.password:
            continue
        try:
            count = check_password(entry.password)
        except BreachCheckError as exc:
            print(f"  ! stopped: {exc}", file=sys.stderr)
            return 1
        if count:
            found += 1
            print(f"  - {entry.name}: seen {count:,} times in breaches. Change it.")
        time.sleep(0.2)  # be polite to the free API
    if not found:
        print("  none of your passwords were found in known breaches.")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    vault = _open(args)
    pw = getpass.getpass("Export password (12+ chars; it protects the backup file): ")
    if pw != getpass.getpass("Confirm: "):
        print("error: passwords don't match", file=sys.stderr)
        return 1
    count = export_encrypted(args.file, vault.all_entries(), pw, overwrite=args.force)
    print(f"Exported {count} entries to {args.file}.")
    print("The export password cannot be recovered. Store the file somewhere safe.")
    return 0


def cmd_import(args: argparse.Namespace) -> int:
    vault = _open(args)
    entries, warnings, kind = load_import(
        Path(args.file), lambda: getpass.getpass("Export file password: ")
    )
    report = vault.import_entries(entries, on_conflict=args.on_conflict)
    print(f"Imported from {kind.upper()}: {report.added} added "
          f"({report.renamed} renamed), {report.skipped} skipped, "
          f"{report.overwritten} overwritten.")
    for warning in warnings[:10]:
        print(f"  note: {warning}")
    if len(warnings) > 10:
        print(f"  ... and {len(warnings) - 10} more notes")
    if kind == "csv":
        print("\nWARNING: that CSV holds your passwords in plain text. Delete it now.")
    return 0


def cmd_ui(args: argparse.Namespace) -> int:
    try:
        from passwordmanager.ui.server import run
    except ImportError:
        print('error: UI dependencies missing. Install with: pip install -e ".[ui]"',
              file=sys.stderr)
        return 1
    run(
        _vault_path(args),
        host=args.host,
        port=args.port,
        auto_lock_seconds=args.auto_lock,
        open_browser=not args.no_browser,
    )
    return 0


def cmd_app(args: argparse.Namespace) -> int:
    try:
        from passwordmanager.app import run_app

        run_app(
            _vault_path(args),
            auto_lock_seconds=args.auto_lock,
            lock_on_minimize=not args.no_lock_on_minimize,
        )
    except ImportError as exc:
        print(f'error: missing dependency ({exc.name}). Install: pip install -e ".[app]"',
              file=sys.stderr)
        return 1
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
    p.add_argument("--totp", action="store_true", help="prompt for a 2FA (TOTP) secret or link")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pm", description="PasswordManager - local encrypted vault")
    p.add_argument("--vault", help="vault file path (default: ~/.passwordmanager/vault.bin)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
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

    s = sub.add_parser("totp", help="show the current 2FA code for an entry")
    s.add_argument("name")
    s.add_argument("--copy", action="store_true", help="copy the code (clears after 15 s)")
    s.set_defaults(func=cmd_totp)

    s = sub.add_parser("audit", help="find reused and weak passwords")
    s.add_argument("--breach", action="store_true", help="also check Have I Been Pwned (network)")
    s.add_argument("-y", "--yes", action="store_true", help="skip the network confirmation")
    s.set_defaults(func=cmd_audit)

    s = sub.add_parser("export", help="write an encrypted backup (.pmbak)")
    s.add_argument("file")
    s.add_argument("--force", action="store_true", help="overwrite an existing file")
    s.set_defaults(func=cmd_export)

    s = sub.add_parser("import", help="import an encrypted export or a CSV from another manager")
    s.add_argument("file")
    s.add_argument("--on-conflict", choices=CONFLICT_MODES, default="rename",
                   help="when a name already exists (default: rename, never loses data)")
    s.set_defaults(func=cmd_import)

    s = sub.add_parser("ui", help="start the local web UI (loopback only)")
    s.add_argument("--host", default="127.0.0.1", help="127.0.0.1, localhost or ::1 only")
    s.add_argument("--port", type=int, default=8765)
    s.add_argument("--auto-lock", type=int, default=300, metavar="SECONDS",
                   help="lock after this many idle seconds (default 300)")
    s.add_argument("--no-browser", action="store_true", help="don't open a browser tab")
    s.set_defaults(func=cmd_ui)

    s = sub.add_parser("app", help="open the desktop app (native window)")
    s.add_argument("--auto-lock", type=int, default=300, metavar="SECONDS")
    s.add_argument("--no-lock-on-minimize", action="store_true")
    s.set_defaults(func=cmd_app)

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
