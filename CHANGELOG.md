# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-09-26

First release on PyPI (published 2026-10-02): `pip install toolkit-ml-provenance`.

### Release and project files

- The PyPI distribution name is now `toolkit-ml-provenance`, matching the repository (was `toolkit-ml-provenance-sbom`, never published). Import paths and CLI commands are unchanged.
- `schemas/report-envelope.v1.json` is now byte-identical to the shared copy used across the toolkit repos.
- Release workflow: a `v*` tag runs the tests, builds the sdist and wheel,
  checks them with `twine check --strict` (twine 6.1 or newer, which reads the
  Metadata 2.4 that setuptools 77+ writes), installs the wheel and checks its
  version against the tag, and attaches both files to a GitHub Release. The
  PyPI upload (Trusted Publishing) runs only when the repository variable
  `PUBLISH_TO_PYPI` is `true`. See `RELEASING.md`.
- CI builds and checks the package the same way on every pull request.
- Package metadata: SPDX license expression `Apache-2.0` with `LICENSE` and
  `NOTICE` in the distributions, author AKIVA AI, LLC, and links to the
  documentation, issues and changelog.
- Added `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1), issue and pull request
  templates and `RELEASING.md`. `SECURITY.md` lists the supported versions and
  the private reporting channel.
- CI runs pyright as well as mypy, and `pip-audit` with every optional extra
  installed instead of the retired `safety check`. The build no longer pins
  setuptools below 77.

### Added
- README five-minute example on a small public Hugging Face model.
- Importers for `generate`: `--from-hf REPO_ID` (new `hf` extra) downloads a Hugging
  Face Hub model at a pinned commit, checks LFS files against the Hub's SHA-256 and
  records repo, commit and card data; `--from-mlflow RUN_DIR` (new `mlflow` extra for
  `MLmodel` parsing) describes a local MLflow file-store run (MLflow 2 and 3 layouts):
  params, final metrics, tags, flavors and requirements. `--include` now defaults to
  `**/*` when an importer is used.
- Unsafe-pickle scan: `scan-pickle` command and a default scan in `generate`
  (`--no-pickle-scan`, `--fail-on-pickle dangerous|unknown`). Stdlib opcode scanner
  that never unpickles; covers raw pickles, PyTorch zip and legacy checkpoints and
  NumPy object arrays. Findings go into the ML-BOM file properties and the report
  envelope. Extracted globals and dangerous verdicts are cross-checked against
  `picklescan` in tests.
- CycloneDX 1.6 ML-BOM (`generate --format cyclonedx`): the model is a
  `machine-learning-model` component with a model card (task, architecture,
  datasets, metrics) derived from `config.json`, the `README.md` front matter and
  `requirements.txt`; files are nested `file` components with SHA-256; datasets are
  `data` components (hashed when local); base models are pedigree ancestors; framework
  and library packages are `pkg:pypi` components; a dependency graph links them. New
  options `--name`, `--model-version`, `--license`, `--base-model`, `--dataset`,
  `--requirements`. Tests validate the output against the official CycloneDX 1.6 schema.
- `sign-model` / `verify-model`: OpenSSF Model Signing (OMS) for model directories
  through the new `oms` extra (`model-signing`), with ECDSA keys or Sigstore keyless.
  Signatures interoperate with the `model_signing` reference implementation.
- `keygen --algorithm ecdsa-p256` for OMS keys.
- `sign-file` / `verify-file`: sign and verify any file (for example any toolkit's
  report envelope) with a DSSE envelope over an in-toto Statement. Ed25519 key mode
  with the `signing` extra; Sigstore keyless mode with the new `sigstore` extra.
  Verification fails closed and requires a pinned identity and issuer in Sigstore mode.
- Report envelope v1 (in-toto Statement, canonical JSON): `generate --report` (kind
  `aibom.generate`), and `verify` output, `verify --out` and `verify --report` (kind
  `aibom.verify`). Spec in `docs/report-envelope.md`, JSON Schema in
  `schemas/report-envelope.v1.json`.

### Changed
- `generate --format cyclonedx` now writes CycloneDX 1.6 (was 1.5). Files are nested
  under the model component instead of being top-level `data` components.
- `verify` JSON output is now the report envelope. The previous report shape is
  available with `--format legacy-json` until 1.1.

### Legal
- Relicensed from MIT to Apache-2.0. Releases before this change remain available under MIT.
  Added a `NOTICE` file.

### Security
- `verify --signature` without `--public-key` no longer skips the check and reports
  `signature_ok: true`. The two flags must be given together (exit 2 otherwise), and
  `signature_ok` is `null` when no signature was checked.
- `verify` now fails on files added inside the manifest's include scope (reason
  `unlisted`). `--allow-extra` reports them without failing. Manifests without
  recorded include globs treat the whole root as the scope.
- The signature is verified over the manifest exactly as stored, so every field is covered.
- `keygen` refuses to overwrite existing key files unless `--force` is given. The
  private key is created with mode 0600 instead of being chmodded after writing.

### Fixed
- Manifests are portable: entry paths are relative with POSIX separators and the root is
  stored relative to the manifest file, so a manifest verifies on another machine or OS.
  `verify --root` points at a relocated model.
- Overlapping include globs (such as `--include "**/*"`) no longer produce duplicate entries.
- `generate` never lists its own output file.
- `verify` explains that it reads the native manifest when given a CycloneDX export.
- Docker image installs the `signing` extra instead of dev tools.

### Changed
- Manifest format version 2 adds an `include` field. Version 1 manifests still verify.
- `verify` reports include an `unlisted` list.
- Documentation rewritten to match the code: capability status table, install from
  source (not yet on PyPI), no claims of byte-for-byte determinism or ML-BOM content.
- Dependabot opens one grouped weekly PR per ecosystem.

### Removed
- The unused `control_plane` package and its tests.
- Unused settings from `.env.example` (`SBOM_FORMAT`, `INCLUDE_DEPENDENCIES`,
  `SCAN_VULNERABILITIES`) that no code read.

### Added
- `--version` flag to CLI
- Public Python API exported from `toolkit_ml_sbom` package (Manifest, build_manifest, sign_bytes, verify_bytes, etc.)
- CycloneDX 1.5 JSON output format via `--format cyclonedx` on generate command
- Structured JSON logging via `--log-format json` flag
- `--format table` option on verify command for human-readable output
- Dependabot configuration for automated dependency updates
- Edge case tests for empty manifests, missing fields, invalid signatures, corrupt files
- CHANGELOG.md

### Changed
- CI security scans (twine check) are now blocking instead of continue-on-error

### Fixed
- README now includes complete CLI reference and output format documentation

## [0.1.0] - 2026-03-09

### Added
- Initial release
- `generate` command: create provenance manifests from file globs
- `verify` command: verify file integrity against manifest
- `keygen` command: generate Ed25519 signing keypairs
- `sign` command: create detached signatures for manifests
- SHA-256 file hashing with chunked reads
- Git commit tracking for provenance
- Docker and docker-compose deployment support
- CI/CD pipeline with multi-Python-version testing
