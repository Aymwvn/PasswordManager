# Changelog

## Unreleased

- **Clipboard (Windows):** passwords and 2FA codes are copied with the clipboard-history and
  cloud-clipboard opt-out formats; cleared after 15 s only if nothing else was copied; cleared when
  the vault locks or the app exits.
- `Vault.lock()` overwrites the derived key's buffer with zeros (best effort).
- **Single instance:** a second launch (for example from a hotkey) brings the running window
  forward instead of starting another copy.
- **Lost-update protection:** a save is refused (HTTP 409) if the vault file changed on disk since
  it was loaded; the in-memory change is rolled back. All vault mutations are now transactional, so
  a failed save (disk full, permissions) no longer leaves memory and disk disagreeing.
- Window title is now "PasswordManager - Local Vault" so the running window can be found
  unambiguously.
- `packaging/create_shortcut.bat` (Ctrl+Alt+P) and `packaging/pm-hotkey.ahk` (Win+Alt+P);
  see `docs/SHORTCUTS.md`.

## 0.4.0

TOTP codes, Have I Been Pwned breach check (k-anonymity), password audit, encrypted
export/import, attested releases.

## 0.3.0

Hardening: CSRF tokens, unlock lockout, body-size cap, bounded KDF parameters, fuzzing, threat
model, self-pentest report.

## 0.2.0

Local web UI and desktop app.

## 0.1.0

Core library, versioned vault format, CLI, tests, CI.
