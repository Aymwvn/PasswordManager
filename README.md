# PasswordManager

![CI](https://github.com/Aymwvn/PasswordManager/actions/workflows/ci.yml/badge.svg)

Local-first, encrypted password manager. Your vault is a single file on your machine.
No cloud, no account, no telemetry.

- **KDF:** Argon2id (64 MiB, t=3, p=4 by default; parameters stored in the vault header)
- **Encryption:** AES-256-GCM, fresh random nonce on every save, header authenticated as AAD
- **Storage:** one encrypted file, written atomically, `0600` permissions on POSIX
- **Interfaces:** desktop app (native window), CLI, and a local web UI (loopback only)

> Status: early development (Phase 2 of 4). Not audited, so don't trust it with your only copy
> of anything important yet.

## Install

```bash
git clone https://github.com/Aymwvn/PasswordManager.git
cd PasswordManager
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[clipboard,app]"
```

## Desktop app

```bash
pm app                          # native window, no browser tab
pm app --auto-lock 120
pm app --no-lock-on-minimize
```

The window is the same UI as below, hosted on a random loopback port that changes on every
launch. The vault locks automatically when the window is minimized, and when the app closes.

### Build a Windows `.exe`

```bat
packaging\build_windows.bat
```

Output: `dist\PasswordManager\PasswordManager.exe` (needs the WebView2 runtime, preinstalled on
Windows 11). Unsigned builds may trigger a SmartScreen warning.

## Web UI (browser)

```bash
pm ui                      # opens http://localhost:8765
pm ui --auto-lock 120      # lock after 2 idle minutes
pm ui --port 9000 --no-browser
```

Create or unlock the vault, search, add/edit/delete entries, generate passwords with a
strength meter, copy a password (the clipboard is cleared after 15 s), and auto-lock on idle.

### UI security model (current)

| Threat | Mitigation |
|---|---|
| Other machines reaching the UI | Server refuses to bind anything but loopback |
| DNS rebinding | `Host` header allow-list (`localhost:PORT`, `127.0.0.1:PORT`) |
| Cross-site request forgery | `Origin` check on writes + `SameSite=Strict` cookie |
| Session theft / replay | Random 256-bit token, `HttpOnly` cookie, rotated on every unlock |
| Walking away from the screen | Idle auto-lock on the server (status polling does not extend it) |
| XSS via vault data | DOM-only rendering (no HTML strings), strict CSP (`script-src 'self'`), no inline JS/CSS |
| Info leaks | `no-store` caching, `Referrer-Policy: no-referrer`, no `/docs` or OpenAPI |

Planned in Phase 3: CSRF tokens, unlock rate limiting, API fuzzing, a self-pentest write-up,
and a written threat model.

## CLI

```bash
pm init                                  # create a vault
pm add github -u aymen --url https://github.com -g   # -g generates a password
pm get github                            # copies the password, clears clipboard after 15s
pm get github --show                     # print instead
pm list
pm search git
pm edit github -g                        # rotate the password
pm delete github
pm gen -l 24                             # standalone generator
```

Vault location: `~/.passwordmanager/vault.bin` (override with `--vault` or `PM_VAULT`).

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
bandit -r src
```

## Roadmap

- [x] Phase 1: core library, versioned vault format, CLI, tests, CI
- [x] Phase 2: local web UI (FastAPI + vanilla JS), auto-lock, Host/Origin checks, CSP
- [x] Phase 2b: desktop app (pywebview) + Windows build script
- [ ] Phase 3: UI hardening (CSRF tokens, rate limiting, API fuzzing, self-pentest write-up)
- [ ] Phase 4: TOTP, breach check (HIBP k-anonymity), threat model, signed releases

## License

TBD
