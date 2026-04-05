# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Email `security@akiva.com` with:

- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Affected versions (if known)

We will acknowledge receipt within 48 hours and provide a triage assessment within 7 business days.

## Disclosure Policy

We follow coordinated disclosure. We ask that you give us 90 days to address the issue before public disclosure.

## Scope

The following are in scope for security reports:

- Cryptographic signing/verification logic (`signing.py`)
- File hashing integrity (`hashing.py`)
- Path traversal or file system access issues (`cli.py`, `manifest.py`)
- Dependency vulnerabilities in `cryptography` optional dependency
- CycloneDX output integrity (`cyclonedx.py`)

The following are out of scope:

- Issues requiring physical access to the machine running the tool
- Denial-of-service via large file inputs (expected behavior for file hashing)
- Issues in development-only dependencies (pytest, ruff, pyright)

## Security Design

- **Zero core dependencies** — the tool uses only Python stdlib in its core path, minimizing supply chain risk
- **Optional cryptography** — Ed25519 signing requires `cryptography>=43.0.0` as an opt-in extra
- **No network calls** — the tool operates entirely on local files (only subprocess call is to `git`)
- **No secrets in manifests** — manifests contain file hashes and metadata only; do not include secrets or credentials in metadata values
- **Private key protection** — private key files are written with restrictive permissions (0o600)
