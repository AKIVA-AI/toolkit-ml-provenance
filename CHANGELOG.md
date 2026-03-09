# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
