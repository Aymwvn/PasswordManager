# Design decisions

Why the project looks the way it does, including the options that were rejected. Each entry says
what was decided, why, what it costs, and when to revisit it. Threats and limits live in
[THREAT_MODEL.md](THREAT_MODEL.md); findings in [SELF_PENTEST.md](SELF_PENTEST.md).

Last reviewed: 2026-11-07. Hardware and OS facts below were checked against the sources listed at
the end; they change, so re-check before relying on them.

| ID | Decision | Status |
|---|---|---|
| [DD-1](#dd-1-no-tee--enclave) | No TEE / enclave | Decided |
| [DD-2](#dd-2-optional-device-bound-key-dpapi--tpm-with-mandatory-recovery) | Optional device-bound key (DPAPI / TPM) with mandatory recovery | Proposed, **not implemented** |
| [DD-3](#dd-3-honest-memory-hygiene-instead-of-enclave-claims) | Honest memory hygiene instead of enclave claims | Partly done |
| [DD-4](#dd-4-no-plaintext-export) | No plaintext export | Decided |
| [DD-5](#dd-5-totp-secrets-live-in-the-same-vault) | TOTP secrets live in the same vault | Decided, trade-off documented |
| [DD-6](#dd-6-loopback-web-server--webview-instead-of-a-native-toolkit) | Loopback web server + webview instead of a native toolkit | Decided, revisit later |
| [DD-7](#dd-7-one-app-instance-and-refuse-to-overwrite-a-vault-changed-elsewhere) | One app instance, and refuse to overwrite a vault changed elsewhere | Done |

---

## DD-1: No TEE / enclave

**Idea evaluated:** run decryption and vault logic inside a hardware-isolated enclave (Intel SGX,
AMD SEV, or a Windows VBS enclave) so that malware or even an administrator cannot read the
secrets from RAM.

**Decision:** not doing it.

**Reasons**

1. **The hardware story doesn't fit a desktop app.**
   - *SGX:* Intel deprecated it on 11th and 12th generation Core client processors and kept it only
     on Xeon. A user's laptop is unlikely to have it.
   - *AMD SEV:* built to protect whole virtual machines from the host in cloud setups. It is not an
     API for isolating one function inside a desktop process.
   - *Windows VBS enclaves:* the only realistic option on Windows, but the current Microsoft docs
     require Windows 11 build 26100.2314 or later (or Windows Server 2025), VBS/HVCI turned on, an
     enclave DLL built with the MSVC C/C++ toolchain against a very small set of allowed libraries,
     a separate native host application, and signing with an enclave-capable certificate. Python
     cannot run inside one, so the crypto core would have to be rewritten in C/C++ (or Rust).
2. **It protects one path, and not the likely one.** An enclave defends secrets in RAM against other
   software. But the master password is typed through the normal keyboard path, and passwords end
   up on the clipboard or on screen. Malware that controls the OS can read those without ever
   touching the enclave.
3. **TEEs have a poor security record on client hardware.** SGX has seen published attacks such as
   Foreshadow and Plundervolt, and it is still receiving security advisories.
4. **Auditability.** The core is a few hundred lines of Python that one person can review in an
   afternoon. A native enclave, its host, and the signing pipeline would be a much larger and
   harder-to-review trusted base, which is bad for a security project.
5. **Portability.** The app runs on any Windows or Linux machine with Python. An enclave would
   restrict it to specific hardware and OS builds.

**Alternatives considered:** SGX (dead on client CPUs), SEV (wrong layer), VBS enclave (Windows 11
only, native rewrite), OS-level isolation such as a separate low-privilege process (reasonable, but
a lot of work for a modest gain).

**Revisit when:** the core is rewritten in a native language for other reasons *and* Windows
enclave tooling is easy to ship; or the goal changes to defending against administrator-level
memory scraping specifically (an enterprise requirement).

---

## DD-2: Optional device-bound key (DPAPI / TPM) with mandatory recovery

**Status:** design only. Nothing here exists in the code yet.

**Goal:** make a *stolen vault file* useless on another machine, even if the master password is
guessable. Today (threat A1) the file's only protection is the master password plus Argon2id.

**Non-goals:** defending against malware running as the logged-in user, or against someone with
physical access who can also type your password.

### What a TPM does and does not give us

| Claim | Reality |
|---|---|
| A TPM-held key is non-exportable | True: the private part never leaves the TPM. |
| It binds the vault to this machine | True, and this is the whole value of the feature. |
| It stops malware | **No.** Malware running as you can ask the TPM to use the key while you are logged in, unless every use needs a PIN or Windows Hello. |
| Anti-hammering "completely mitigates brute force" | **Overstated.** The lockout counter is *global* to the TPM, not per key. Microsoft's current docs describe a lockout after 32 authorization failures and one failure forgiven per 10 minutes. It only applies to keys that have an authorization value; a key without one has nothing to hammer. |
| Sealing to PCRs detects tampering | True, but brittle: firmware and OS updates change the measurements, and users get locked out. This is the same mechanism behind BitLocker recovery prompts. **We would not use PCR sealing by default.** |

Consequence of the global lockout: our app must **not** give its key a typed PIN and count
failures on the TPM. A flood of wrong guesses could lock the TPM for Windows itself (Windows Hello,
BitLocker). We keep our own rate limiter (already in the UI) and, if we want user presence, we
ask the OS (Windows Hello) rather than managing authorization values ourselves.

### Levels

| Level | Mechanism | Protects against | Weakness |
|---|---|---|---|
| L0 (today) | master password + Argon2id | file theft, if the password is strong | a weak password falls to offline guessing |
| L1 | random `device_secret` wrapped with Windows DPAPI | the file copied to another machine or user | any process as the same user can unwrap it |
| L2 | `device_secret` wrapped by a non-exportable TPM key (CNG TPM key storage provider) | same, plus the key cannot be copied off the machine | same-user malware can still ask the TPM; TPM clear or hardware change loses the secret |
| L3 (maybe never) | L2 plus Windows Hello per unwrap | same-user malware without the user present | complexity, and it ties us to Windows Hello behaviour |

### Proposed vault format v2 (LUKS-style key slots)

```
data_key       random 256-bit key, encrypts the payload with AES-256-GCM (as today)
device_secret  random 32 bytes, stored only as a DPAPI/TPM-wrapped blob next to the vault

slot "password":  KEK = HKDF-SHA256(argon2id(master, salt) || device_secret)  ->  AES-GCM(data_key)
slot "recovery":  KEK = HKDF-SHA256(recovery_key)                             ->  AES-GCM(data_key)
```

- The whole header, including both slots, is authenticated (AAD), as in v1.
- `recovery_key` is 256 random bits, shown **once** at enable time, never stored.
- A side benefit: changing the master password only re-wraps one slot instead of re-encrypting
  everything.

### Recovery is mandatory, not optional

| Event | Password only (L0) | Device-bound + recovery slot | Device-bound, no recovery |
|---|---|---|---|
| Vault file stolen, attacker has no access to the machine | offline guessing against Argon2 | needs the password **and** the device secret | same |
| Motherboard dies or TPM is cleared | fine | open with the recovery key, or restore a `.pmbak` | **vault lost** |
| Windows reinstalled | fine | recovery key or `.pmbak` | likely lost |
| Master password forgotten | lost | lost | lost |
| Malware as the user while unlocked | reads everything | same | same |

Enabling the feature must refuse to finish until: (1) an encrypted export (`.pmbak`) has been
written **and test-imported into a temporary vault**, and (2) the user has re-typed the recovery
key. "Works on my machine until the day it doesn't" is the failure mode this guards against.

### Implementation plan

1. A small interface: `DeviceKeyProvider { available(); wrap(secret) -> bytes; unwrap(blob) -> secret }`.
2. Providers: `FakeProvider` (tests, including a "wrong machine" mode where `unwrap` fails),
   `DpapiProvider` (Windows, `ctypes`), `TpmProvider` (Windows CNG TPM key storage provider).
3. All key-slot logic and the recovery flow are tested in CI with the fake provider. Only the two
   real providers need a Windows machine.
4. Opt-in: `pm device-key enable` and `pm device-key disable` (disable re-wraps the vault without
   the device factor). Default stays L0.

### Things that must be verified on real hardware before trusting this

- RSA-OAEP decryption through the TPM key storage provider works as assumed, and its latency.
- What survives a Windows reinstall, a user-profile change, and a TPM clear (we assume nothing).
- Behaviour on machines with a firmware TPM versus a discrete one, and in a VM.
- That a Python `ctypes` binding to the CNG functions is reliable enough, or whether a small
  native helper is safer.

All first tests on a throwaway vault, never on real data.

**Revisit when:** there is a Windows test machine available and a stable recovery flow.

---

## DD-3: Honest memory hygiene instead of enclave claims

**Context:** Python strings and bytes are immutable and may be copied by the interpreter and by
libraries. We cannot guarantee that secrets are wiped from RAM, so we do not claim it.

**Done today**

- `Vault.lock()` drops the key and the decrypted entries.
- Idle auto-lock runs on the server, and status polling does not extend it. The desktop app also
  locks on minimize.
- Passwords are shown only on request (Reveal).
- Windows: copied passwords and 2FA codes go to the clipboard through the native API with the
  history and cloud-clipboard opt-out formats set. The 15-second clear only fires if the clipboard
  sequence number shows nothing else was copied meanwhile, and the clipboard is also cleared when
  the vault locks or the app exits. Elsewhere the browser clipboard is the weaker fallback.
- `Vault.lock()` overwrites the derived key's buffer (a `bytearray`) with zeros. This shrinks the
  window but is not a guarantee: copies held by the interpreter or the crypto library are out of
  reach.
- No request body is logged by our code; the server runs at warning level.

**Not done (candidate follow-ups)**

- Scrub the copies of the key and the entry strings that Python and the crypto library hold
  (not possible from pure Python).
- Lock memory pages to keep secrets out of the swap file.
- Measure the real effect with a process memory dump after locking (checklist item 13 in the
  self-pentest report). We expect to find residue and will document it.

---

## DD-4: No plaintext export

**Decision:** export exists only as an encrypted `.pmbak` file protected by its own password. CSV
is import-only.

**Why:** a decrypted dump of every secret in a Downloads folder, a backup tool or a cloud-synced
directory is exactly what a password manager is supposed to prevent.

**Cost:** moving away from this tool means decrypting a `.pmbak` ourselves. The container format is
documented in `core/crypto.py` and the payload inside is plain JSON, so it is not a trap, but it is
less convenient than a CSV.

**Revisit when:** users need an easy exit path. The likely answer is an explicit, loudly-warned
flag, not a default.

---

## DD-5: TOTP secrets live in the same vault

**Trade-off:** one place for passwords and 2FA codes is convenient, but anyone who unlocks the
vault gets both, so the two factors collapse into one.

**Decision:** keep the feature, make it optional, and say so plainly in the README and threat
model. High-value accounts (email, banking) should keep their second factor on a separate device
or a hardware key.

---

## DD-6: Loopback web server + webview instead of a native toolkit

**Why:** one UI serves both the browser and the desktop window, it reuses web skills, and the whole
API is testable without a display (FastAPI's test client).

**Cost:** a local HTTP port is an attack surface (other local users and processes, malicious web
pages, DNS rebinding). Phase 3 addressed this with a Host allow-list, Origin and `Sec-Fetch-Site`
checks, a per-session CSRF token, session cookies bound to each unlock, lockout on repeated failed
unlocks, a request-size cap, and a strict CSP. See the threat model and the live attack replay.

**Alternatives:** Qt or Tk (extra dependency and a different UI codebase); Electron (large bundle,
a big Node supply chain).

**Revisit when:** the desktop app should drop the TCP port entirely. pywebview's JavaScript bridge
would let the window talk to Python directly, removing the localhost listener for desktop mode.

---

## DD-7: One app instance, and refuse to overwrite a vault changed elsewhere

**Context:** adding a global hotkey made a double launch easy. Every save rewrites the whole file
from the in-memory copy, so with two writers (two app windows, or the app and the CLI) the second
save silently discards the first one's changes. This lost-update bug existed from the first
version.

**Decision**

1. A named mutex per vault path. A second launch finds the running window by its exact title,
   restores and raises it, and exits without starting anything.
2. Every save compares the SHA-256 of the file on disk with what we last read or wrote. If it
   differs, the save is refused (`VaultChangedOnDisk`, HTTP 409), nothing is written, and the
   in-memory change is rolled back. Lock and unlock reloads it.
3. All mutations are transactional: any failed save (changed file, disk full, permissions) rolls
   the in-memory state back, so memory and disk cannot silently disagree.

**Alternatives:** OS file locking (platform quirks, stale locks after a crash); merging concurrent
edits (needs per-entry versions and a conflict UI); a background sync service (out of scope).

**Consequences:** no silent data loss, but also no merge. A tiny race between the check and the
replace remains. The check is content-based, so a sync tool that rewrites identical bytes is not a
conflict. The window title is deliberately more specific than "PasswordManager", because an
Explorer window for a folder of that name has exactly that title.

**Revisit when:** multi-device sync is built; that needs per-entry timestamps and merging.

---

## Sources checked (2026-11-07)

- Intel SGX deprecation on 11th/12th gen Core client CPUs, continued on Xeon:
  <https://en.wikipedia.org/wiki/Software_Guard_Extensions> and an Intel community answer at
  <https://community.intel.com/t5/Intel-Software-Guard-Extensions/Is-Intel-SGX-supported-in-13th-gen-Intel-processors/m-p/1710744>
- VBS enclave requirements and development flow:
  <https://learn.microsoft.com/windows/win32/trusted-execution/vbs-enclaves> and
  <https://learn.microsoft.com/windows/win32/trusted-execution/vbs-enclaves-dev-guide>
- Clipboard history and cloud-clipboard opt-out formats (`CanIncludeInClipboardHistory`,
  `CanUploadToCloudClipboard`, `ExcludeClipboardContentFromMonitorProcessing`):
  <https://learn.microsoft.com/en-us/windows/win32/dataxchg/clipboard-formats>
- TPM key protection, non-exportability, sealing, and the global dictionary-attack lockout:
  <https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/tpm-fundamentals>
