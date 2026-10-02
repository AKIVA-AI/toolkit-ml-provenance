# Security policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 1.0.x   | Yes       |
| < 1.0   | No        |

Security fixes are released as patch versions of the latest minor release.

## Reporting a vulnerability

Please do not report security problems in a public issue, pull request or
discussion. Report them privately through GitHub: open this repository's
**Security** tab and choose **Report a vulnerability**
(<https://github.com/AKIVA-AI/toolkit-ml-provenance/security/advisories/new>). Include:

- what the problem is and its impact;
- steps or input files to reproduce it;
- the affected version or commit.

We aim to acknowledge a report within 7 days and ask for up to 90 days to
release a fix before public disclosure. We credit reporters who want to be
credited.

## Scope

In scope:

- Signing and signature verification (`signing.py`, `cli.py verify`)
- Integrity checks: any way to make `verify` pass on modified, missing or added
  files (`cli.py`, `manifest.py`, `hashing.py`)
- Path traversal or unintended file system access
- CycloneDX output integrity (`cyclonedx.py`)

Out of scope:

- Issues requiring physical access to the machine running the tool
- Denial of service via very large inputs (hashing large files is expected)
- Vulnerabilities in development-only dependencies (pytest, ruff, pyright)

## Security design and limits

- **Fail closed.** `verify` fails on modified, missing and unlisted files. A
  signature check runs only with both `--signature` and `--public-key`; giving
  one without the other is an error, and `signature_ok` is `null` when no
  check ran. `verify-file` needs exactly one mode (`--public-key`, or
  `--identity` with `--issuer`) and checks both the signature and that the
  signed payload covers the file on disk.
- **Pickles are never loaded.** The pickle scan only walks opcodes with
  `pickletools`; it is a static check and can miss what it cannot resolve
  (reported as `unknown` or `dangerous`, never `safe`).
- **Zero core dependencies.** The core uses only the Python standard library.
  Ed25519 signing uses the optional `cryptography` extra.
- **No network calls in the core.** The only subprocess call is
  `git rev-parse HEAD`. Sigstore mode (optional extra) contacts Sigstore's
  public services (TUF, Fulcio, Rekor) and, for `sign-file --sigstore`, an
  OIDC provider. OIDC tokens are never written to the audit log.
- **No secrets in manifests.** Manifests hold file hashes and the metadata you
  pass with `--meta`; do not put secrets there.
- **Private keys** are unencrypted PKCS#8 PEM files. On POSIX they are created
  with mode `0600`; on Windows the mode has no effect, so protect them with
  file ACLs. `keygen` refuses to overwrite existing keys without `--force`.
  There is no passphrase or KMS/HSM support; use Sigstore keyless mode to
  avoid long-lived keys.
- **Signature formats.** `sign-file` writes standard DSSE envelopes over
  in-toto Statements (Ed25519) or Sigstore bundles. The older `sign` command
  writes a detached JSON object specific to this tool and is kept for
  manifest compatibility.
