# Releasing and verifying downloads

## Cutting a release

1. Bump `version` in `pyproject.toml` and `src/passwordmanager/__init__.py` (they must match).
2. Commit and push to `main`, wait for CI to be green.
3. Tag and push: `git tag -a v0.4.0 -m "v0.4.0" && git push origin v0.4.0`

The **Release** workflow (`.github/workflows/release.yml`) then:

| Step | What happens |
|---|---|
| verify | tag must equal the package version, then `ruff`, `bandit`, and the full test suite |
| build-python | sdist and wheel (`python -m build`) |
| build-windows | PyInstaller build of `PasswordManager.exe`, zipped |
| publish | `SHA256SUMS.txt`, a **Sigstore build-provenance attestation** for every artifact, then a GitHub Release |

**Dry run:** Actions tab, Release, *Run workflow*. It builds everything and publishes nothing.
Do this once before your first real tag: the Windows build has only ever been run locally.

## Verifying a download

```bash
# 1. checksum
sha256sum -c SHA256SUMS.txt                 # Windows: Get-FileHash .\file.zip -Algorithm SHA256

# 2. provenance (needs the GitHub CLI >= 2.49)
gh attestation verify PasswordManager-v0.4.0-windows-x64.zip --repo Aymwvn/PasswordManager
```

A successful `gh attestation verify` proves the file was produced by **this repository's
Release workflow**, at a specific commit, and has not been modified since. It is signed
keylessly through GitHub's OIDC identity and recorded in a public transparency log.

## What this does *not* give you

- **No Authenticode signature.** Windows SmartScreen may warn on first run because the `.exe` has no
  publisher certificate. Attestations are a different mechanism and Windows does not read them.
  Options when it matters: [SignPath Foundation](https://signpath.org/) (free for open source,
  needs an application) or Azure Trusted Signing (paid).
- **It doesn't prove the code is bug-free**, only where the binary came from. A compromised
  maintainer account or workflow would produce validly attested malicious builds, which is why the
  workflow is small, uses least-privilege `permissions`, and Dependabot keeps the actions current.
- **Builds are not bit-for-bit reproducible** yet.

## Supply-chain notes

- Only the `publish` job has `contents: write`, `id-token: write` and `attestations: write`;
  every other job is read-only.
- Tag names reach shell steps through environment variables, never by direct interpolation.
- Actions are pinned to major versions and bumped by Dependabot. Pinning to full commit SHAs is
  the stricter next step.
