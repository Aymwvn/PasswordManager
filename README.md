# PasswordManager

![CI](https://github.com/Aymwvn/PasswordManager/actions/workflows/ci.yml/badge.svg)

Local-first, encrypted password manager. Your vault is a single file on your machine.
No cloud, no account, no telemetry.

- **KDF:** Argon2id (64 MiB, t=3, p=4 by default; parameters stored in the vault header)
- **Encryption:** AES-256-GCM, fresh random nonce on every save, header authenticated as AAD
- **Storage:** one encrypted file, written atomically, `0600` permissions on POSIX
- **Interfaces:** CLI today; hardened localhost web UI on the roadmap

> Status: early development (Phase 1 of 4). Not audited, so don't trust it with your only copy
> of anything important yet.

## Install

```bash
git clone https://github.com/Aymwvn/PasswordManager.git
cd PasswordManager
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[clipboard]"
```

## Usage

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
- [ ] Phase 2: web UI (FastAPI + frontend)
- [ ] Phase 3: UI hardening (CSRF, Host/Origin checks, CSP, rate limiting, auto-lock)
- [ ] Phase 4: TOTP, breach check (HIBP k-anonymity), threat model, signed releases

## License

TBD
