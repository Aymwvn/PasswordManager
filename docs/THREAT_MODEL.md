# Threat model

Scope: PasswordManager v0.4 (core library, CLI, local web UI, desktop shell).
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
| A7 | Hands the user a malicious import file (tampered `.pmbak`, CSV from a compromised source) | Crafted fields, huge files, line breaks and control characters, bad TOTP secrets | Separate authenticated `PMEX` container, size caps (50 MiB / 10 MiB / 100 000 rows), strict types, field limits, control characters rejected or cleaned, all-or-nothing import that renames instead of overwriting | `test_portability.py`, `test_fuzz.py` |
| A8 | Network observer, or the breach-check service itself | Sees or manipulates the Have I Been Pwned lookup | Opt-in only (explicit click or `--breach`, with a confirmation), only a 5-hex-char SHA-1 prefix is sent, response padding requested, HTTPS with certificate verification, redirects refused, 2 MB response cap, 8 s timeout, `POST` + CSRF so a web page can't trigger it | `test_breach.py`, `test_ui.py` |

## Out of scope / known limitations

These are real limits, not oversights. Where a mitigation exists but is partial, it says so.

1. **Malware running as the same user** (keylogger, debugger, memory scraper) defeats any password
   manager. We do not claim otherwise.
2. **No guaranteed memory wiping.** Python strings and bytes are immutable and may be copied.
   `Vault.lock()` overwrites the derived key's buffer with zeros and drops the decrypted entries,
   but copies made by the interpreter or the crypto library, and the entry strings themselves,
   cannot be scrubbed from Python. A memory dump after locking may still contain secrets.
   Mitigation: short auto-lock and lock on minimize. Fixing this properly means a native core.
3. **Clipboard.** On Windows (desktop app, `pm ui`, CLI) passwords and 2FA codes are copied with
   the clipboard-history and cloud-clipboard opt-out formats set, are cleared after 15 s *only if
   nothing else was copied meanwhile* (checked with the clipboard sequence number), and are cleared
   again when the vault locks or the app exits. Limits: the opt-out formats are a convention.
   Windows' own history and cloud clipboard honour them, but some third-party clipboard managers
   ignore them, and any program watching the clipboard can read the value during those 15 s.
   Where the native path is unavailable (non-Windows, or a plain browser without the server-side
   copy) the browser clipboard API is used instead; it cannot tell whether the clipboard still
   holds our value and cannot opt out of history.
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
10. **TOTP in the same vault is one factor, not two.** Anyone who unlocks the vault gets the password
    *and* the 2FA code. That trades some security for convenience. Keep the second factor for
    high-value accounts (email, banking, the master-password recovery path) on a separate device
    or a hardware key.
11. **Exports and imports.** An encrypted export is only as strong as its export password; anyone
    holding the file can attack it offline. There is deliberately no plaintext export. CSV *imports*
    leave a plaintext file on disk: delete it, but deletion does not guarantee erasure on SSDs,
    backups or cloud-synced folders.
12. **Breach check.** The remaining leak is the fact that you queried the service (IP, timing)
    plus the 5-character prefix. A malicious or compromised response can only produce a false
    "not found" or a false alarm; it cannot make the app reveal the password.
13. **Password audit is heuristic** (pool-size entropy, repetition, reuse). It knows nothing about
    dictionary words or leaked patterns, so "not flagged" is not proof of strength.
14. **Concurrent writers are detected, not merged.** Every save rewrites the whole file from
    memory. The app refuses to save if the file changed on disk since it was loaded, and refuses to
    run twice on one vault, but it cannot merge two people's edits: you lock, unlock and redo the
    change. A small window between the check and the file replace remains, and a sync tool that
    rewrites the file with different bytes will cause (safe) conflicts.

