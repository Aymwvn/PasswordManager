# PasswordManager

![CI](https://github.com/Aymwvn/PasswordManager/actions/workflows/ci.yml/badge.svg)

Local-first, encrypted password manager. Your vault is a single file on your machine.
No cloud, no account, no telemetry.

- **KDF:** Argon2id (64 MiB, t=3, p=4 by default; parameters stored in the vault header)
- **Encryption:** AES-256-GCM, fresh random nonce on every save, header authenticated as AAD
- **Storage:** one encrypted file, written atomically, `0600` permissions on POSIX
- **Extras:** 2FA (TOTP) codes, password audit, opt-in breach check (k-anonymity), encrypted export/import
- **Interfaces:** desktop app (native window), CLI, and a local web UI (loopback only)

> Status: v0.4 (all four planned phases done), still unaudited. Not audited, so don't trust it with your only copy
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

### UI security model

| Threat | Mitigation |
|---|---|
| Other machines reaching the UI | Server refuses to bind anything but loopback; desktop app uses a random port |
| DNS rebinding | `Host` header allow-list |
| Cross-site request forgery | `Origin` + `Sec-Fetch-Site` checks, `SameSite=Strict` cookie, **per-session CSRF token** on every write |
| Session theft / replay | Random 256-bit token, `HttpOnly` cookie, rotated (with the CSRF token) on every unlock |
| Password guessing through the UI | Exponential lockout (5 s, 10 s, 20 s ... 15 min), rejected before any Argon2 work |
| Oversized / malformed requests | 128 KiB body cap (also for chunked uploads), strict input models, fuzzed |
| Hostile vault files | Authenticated header, bounded KDF parameters, clean errors, fuzzed |
| Walking away from the screen | Server-side idle auto-lock; status polling does not extend it; lock on minimize (desktop) |
| XSS via vault data | DOM-only rendering, strict CSP (`script-src 'self'`), no inline JS/CSS, only `http(s)` links |
| Hostile import files | Own authenticated container for exports, size and row caps, strict field validation, all-or-nothing import |
| Breach-check privacy | Opt-in, 5-character hash prefix only, `POST` + CSRF, HTTPS, no redirects |
| Info leaks | `no-store` caching, `Referrer-Policy: no-referrer`, no `/docs` or OpenAPI, no CORS |

Details, limitations and test evidence: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md),
[docs/SELF_PENTEST.md](docs/SELF_PENTEST.md), [SECURITY.md](SECURITY.md).

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
pm totp github                           # current 2FA code (add with: pm add ... --totp)
pm audit                                 # reused and weak passwords (local only)
pm audit --breach                        # also check Have I Been Pwned (asks first)
pm export backup.pmbak                   # encrypted backup, protected by its own password
pm import backup.pmbak                   # or a CSV from Chrome/Edge/Firefox/Bitwarden/1Password
pm --version
```

Vault location: `~/.passwordmanager/vault.bin` (override with `--vault` or `PM_VAULT`).

## 2FA codes (TOTP)

Store an authenticator secret (or paste the `otpauth://` link) with an entry:

```bash
pm add github -u aymen -g --totp         # prompts (hidden) for the secret or link
pm totp github                           # 123 456   (valid for 17s)
```

The UI shows the code with a countdown. Implemented with the standard library and checked
against all RFC 6238 test vectors. Note that keeping passwords and 2FA codes in one vault makes
them one factor, see the [threat model](docs/THREAT_MODEL.md).

## Password audit and breach check

`pm audit` flags reused and weak passwords locally. The breach check uses Have I Been Pwned's
range API with k-anonymity: only the **first 5 hex characters of the password's SHA-1** are sent,
never the password. It always asks first (`--breach`, or the UI's *Check* button).

## Backup, export and import

```bash
pm export backup.pmbak                   # encrypted with its own password (12+ chars)
pm import backup.pmbak                   # prompts for that password
pm import chrome-passwords.csv           # then delete the CSV: it's plaintext
pm import file --on-conflict skip        # default is rename, which never loses data
```

There is deliberately **no plaintext export**.

## Releases and verifying downloads

Release builds are produced by GitHub Actions with Sigstore build-provenance attestations:

```bash
sha256sum -c SHA256SUMS.txt
gh attestation verify PasswordManager-vX.Y.Z-windows-x64.zip --repo Aymwvn/PasswordManager
```

Details and limits (no Authenticode signature yet): [docs/RELEASING.md](docs/RELEASING.md).

## Development

```bash
pip install -e ".[dev]"
pytest                       # includes property-based fuzzing (Hypothesis)
PM_FUZZ_EXAMPLES=500 pytest tests/test_fuzz.py   # deeper fuzz run
ruff check .
bandit -r src
python scripts/attack_replay.py   # live attack replay, prints a results table
```

## Roadmap

- [x] Phase 1: core library, versioned vault format, CLI, tests, CI
- [x] Phase 2: local web UI (FastAPI + vanilla JS), auto-lock, Host/Origin checks, CSP
- [x] Phase 2b: desktop app (pywebview) + Windows build script
- [x] Phase 3: hardening (CSRF tokens, unlock lockout, body cap, fuzzing), threat model, self-pentest report
- [x] Phase 4: TOTP, breach check (HIBP k-anonymity), password audit, encrypted export/import, attested releases

## License

MIT. See [LICENSE](LICENSE).