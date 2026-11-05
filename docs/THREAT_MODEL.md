# Threat model

Scope: PasswordManager v0.3 (core library, CLI, local web UI, desktop shell).
Status: self-reviewed, **not independently audited**.

## What we protect

| Asset | Notes |
|---|---|
| Entry secrets | passwords, usernames, URLs, notes, and entry *names* (the whole payload is encrypted) |
| Master password | never stored; only used to derive the key |
| Vault file integrity | any modification must be detected, never silently accepted |

## Adversaries and what stops them

| # | Adversary | Capability | Controls | Verified by |
|---|---|---|---|---|
| A1 | Gets a copy of the vault file (stolen laptop, leaked backup) | Offline guessing at full speed | Argon2id (64 MiB, t=3, p=4), AES-256-GCM, random salt and per-save nonce, 12-char minimum | `test_crypto.py`, `test_vault.py` |
| A2 | Malicious website open in the user's browser | Sends cross-site requests, tries DNS rebinding, tries to frame the UI | Host allow-list, Origin + `Sec-Fetch-Site` checks, per-session CSRF token, `SameSite=Strict` cookie, no CORS headers, `frame-ancestors 'none'` | `test_ui.py`, `scripts/attack_replay.py` |
| A3 | Another local user or process that can reach the loopback port | Connects to the UI, guesses the master password | Loopback-only bind, random port in the desktop app, session cookie + CSRF token on everything, unlock lockout (5s, 10s, 20s ... 15 min), body cap | `test_ui.py`, `test_fuzz.py` |
| A4 | Shoulder surfer / unattended unlocked machine | Physical or visual access for a short time | Idle auto-lock (server side), lock on minimize (desktop), reveal-on-demand, clipboard auto-clear | `test_ui.py`, `test_app.py` |
| A5 | Hands the user a malicious or corrupted vault file | Crafted header, truncated or bit-flipped file | Authenticated header (AAD), bounded KDF parameters, library errors mapped to clean errors | `test_fuzz.py`, `test_crypto.py` |
| A6 | Malicious *content* inside an entry (e.g. imported data) | Tries to run script in the UI | DOM-only rendering (test bans HTML-string APIs), strict CSP with no inline script, only `http(s)` URLs become links | `test_ui.py::test_frontend_never_uses_innerhtml` |

## Out of scope / known limitations

These are real limits, not oversights. Where a mitigation exists but is partial, it says so.

1. **Malware running as the same user** (keylogger, debugger, memory scraper) defeats any password
   manager. We do not claim otherwise.
2. **No guaranteed memory wiping.** Python strings and bytes are immutable and may be copied;
   `Vault.lock()` drops references but cannot scrub RAM. A memory dump after locking may still
   contain secrets. Mitigation: short auto-lock. Fixing this properly means a native core.
3. **Clipboard.** Copied passwords are cleared after 15 s, but the browser/WebView clipboard API
   cannot tell whether the clipboard still holds *our* value, so the clear may also wipe
   something the user copied meanwhile. Other software (clipboard managers, Windows clipboard
   history) can capture the value before it is cleared.
4. **Unlock throttling is in-memory.** Restarting the app resets it. It protects the UI path;
   offline attacks (A1) are only slowed by Argon2.
5. **No rollback protection.** Someone who can write the vault file can swap in an older valid
   copy (same master password) and the app cannot tell.
6. **Metadata.** File size roughly reveals how much data is stored (no padding).
7. **Plain HTTP on loopback** (no TLS, cookie not `Secure`). Reaching loopback traffic already
   requires local privileges (see 1).
8. **Weak master passwords.** We enforce length only, not quality.
9. **Single user, single vault, no sync, no recovery.** Forgetting the master password means the
   data is gone by design.
