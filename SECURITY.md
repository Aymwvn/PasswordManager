# Security policy

PasswordManager is an **unaudited**, early-stage project. Please don't rely on it as the only copy
of anything important.

## Reporting a vulnerability

Use GitHub's private reporting: **Security tab, Report a vulnerability**. Please don't open a
public issue for security bugs. Include steps to reproduce and the version (`pm --help` / `pip show passwordmanager`).
This is a personal project: there is no bounty and responses are best-effort, but reports are welcome and credited.

## Scope

In scope: the vault format and crypto, the CLI, the local web UI/API, the desktop shell.
See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for what is and is not defended, and
[docs/SELF_PENTEST.md](docs/SELF_PENTEST.md) for what has already been found and fixed.

Out of scope: attacks that require malware already running as the same user, and the limitations
listed in the threat model.
