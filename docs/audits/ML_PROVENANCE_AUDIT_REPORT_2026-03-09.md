# toolkit-ml-provenance System Audit Report

**Date:** 2026-03-09
**Auditor:** Claude Code (Automated)
**Archetype:** 9 -- Developer Tool / CLI
**Previous Audit:** None (initial audit)

## Composite Score: 62.9/100

| # | Dimension | Weight | Score (0-10) | Weighted | Status |
|---|-----------|--------|-------------|----------|--------|
| 1 | Architecture Integrity | 8% | 8 | 6.4 | PASS |
| 2 | Authentication & Authorization | 2% | 3 | 0.6 | N/A for CLI |
| 3 | Data Isolation & RLS | 0% | 0 | 0.0 | N/A |
| 4 | API Surface Quality | 12% | 7 | 8.4 | PASS |
| 5 | Data Layer Integrity | 2% | 5 | 1.0 | -- |
| 6 | Frontend Quality | 0% | 0 | 0.0 | N/A |
| 7 | Testing & QA | 15% | 7 | 10.5 | PASS (min 7) |
| 8 | Security Posture | 10% | 7 | 7.0 | PASS (min 6) |
| 9 | Observability & Monitoring | 5% | 5 | 2.5 | -- |
| 10 | Deployment & Infrastructure | 10% | 7 | 7.0 | PASS (min 6) |
| 11 | Documentation Accuracy | 10% | 6 | 6.0 | PASS (min 6) |
| 12 | Domain Capability Depth | 8% | 7 | 5.6 | PASS (min 6) |
| 13 | AI/ML Capability | 5% | 5 | 2.5 | -- |
| 14 | Connectivity & Channel Interface | 2% | 2 | 0.4 | -- |
| 15 | Agentic UI/UX | 0% | 0 | 0.0 | N/A |
| 16 | User Experience & Interface | 0% | 0 | 0.0 | N/A |
| 17 | User Journey & Persona Alignment | 0% | 0 | 0.0 | N/A |
| 18 | Zero Trust Architecture | 2% | 3 | 0.6 | -- |
| 19 | Enterprise Security & Compliance | 5% | 5 | 2.5 | -- |
| 20 | Operational Readiness | 2% | 4 | 0.8 | -- |
| 21 | Agentic Workspace | 2% | 2 | 0.4 | -- |
| | **Total** | **100%** | | **62.9** | |

**Minimum checks:** Dim 7: 7 (PASS), Dim 4: 7 (PASS), Dim 8: 7 (PASS), Dim 10: 7 (PASS), Dim 11: 6 (PASS), Dim 12: 7 (PASS). Composite 62.9 >= 60 (PASS).

---

## Dimension 1: Architecture Integrity (Score: 8)

**Weight: 8%**

### Findings
- Clean single-package architecture: `toolkit_ml_sbom` with 4 focused modules (cli, manifest, hashing, signing)
- Total source: ~698 LOC across 6 files -- appropriately scoped for a CLI tool
- No circular dependencies; clear module boundaries (hashing -> manifest -> cli, signing -> cli)
- `pyproject.toml` properly configures setuptools with src layout, entry point `toolkit-mlsbom`
- Build system uses setuptools with proper package discovery
- `pyrightconfig.json` configured for type checking (basic mode)
- Minor: subprocess call in `manifest.py` line 18 uses `nosec` annotation, properly guarded with timeout

### Gaps
- No `py.typed` marker file found (declared in package-data but not verified present)

---

## Dimension 2: Authentication & Authorization (Score: 3)

**Weight: 2%**

### Findings
- Ed25519 keypair generation and signature verification implemented in `signing.py`
- Signing is optional (separate `[signing]` dependency group)
- No user authentication (appropriate for a local CLI tool)
- Private key files written with no file permission restrictions (no `chmod 600` equivalent)

### Gaps
- Private key file permissions not set on write (line 230 of cli.py)

---

## Dimension 3: Data Isolation & RLS (Score: 0)

**Weight: 0% -- N/A for CLI tool**

---

## Dimension 4: API Surface Quality (Score: 7)

**Weight: 12%**

### Findings
- Well-structured CLI with 4 subcommands: `generate`, `keygen`, `sign`, `verify`
- argparse with required/optional args, help text on every argument
- Consistent exit codes: 0 (success), 2 (CLI error), 3 (unexpected), 4 (verification failed)
- JSON output format for all commands (manifest, signature, verification report)
- `Manifest` dataclass with `to_json()` / `from_json()` serialization
- Proper input validation via `_validate_path_for_read` / `_validate_path_for_write`
- `canonical_json_bytes` for deterministic signing

### Gaps
- No `--version` flag on CLI
- No programmatic Python API exported from `__init__.py` (only `__version__`)
- No schema versioning for manifest format (version field exists but no migration path)

---

## Dimension 5: Data Layer Integrity (Score: 5)

**Weight: 2%**

### Findings
- JSON file I/O with proper encoding (UTF-8)
- SHA-256 file hashing with 1MB chunk reads (memory-efficient)
- Manifest includes file size, hash, relative path
- Git commit captured for provenance

### Gaps
- No database layer (appropriate for CLI)
- No file locking on writes

---

## Dimension 6: Frontend Quality (Score: 0)

**Weight: 0% -- N/A**

---

## Dimension 7: Testing & QA (Score: 7)

**Weight: 15%**

### Findings
- 2 test files: `test_manifest.py` (100 lines), `test_enhancements.py` (366 lines) = 466 total test LOC
- Coverage configured with `fail_under = 70` (branch coverage enabled)
- CI matrix tests Python 3.10, 3.11, 3.12
- Ruff linting configured with E, F, I, B, UP rule sets
- Pyright type checking configured

### Gaps
- No integration tests for CLI end-to-end workflows
- No property-based testing (e.g., hypothesis)
- Test-to-source ratio is adequate (~0.67:1) but could be higher

---

## Dimension 8: Security Posture (Score: 7)

**Weight: 10%**

### Findings
- Ed25519 signing using `cryptography` library (industry standard)
- `nosec` annotations on subprocess calls with timeout guards
- No hardcoded secrets in source
- No `eval()`, `exec()`, or `shell=True`
- CI includes `bandit` and `safety` security scanning
- SECURITY.md present (minimal but exists)
- Optional dependency pattern prevents signing code from loading unless needed

### Gaps
- No Dependabot configuration found
- No SAST beyond bandit
- Private key files written without restrictive permissions

---

## Dimension 9: Observability & Monitoring (Score: 5)

**Weight: 5%**

### Findings
- Python `logging` module used consistently throughout
- `--verbose` flag enables DEBUG level logging
- Log format includes timestamp, level, message
- Logs go to stderr (stdout reserved for data output)

### Gaps
- No structured logging (JSON format)
- No metrics collection
- No tracing / span support
- No health check endpoint (CLI tool, but could have a `status` subcommand)

---

## Dimension 10: Deployment & Infrastructure (Score: 7)

**Weight: 10%**

### Findings
- Dockerfile present: python:3.11-slim base, proper layer ordering
- docker-compose.yml with volume mounts for sboms/reports/models
- `pyproject.toml` with proper setuptools config, entry point
- CI pipeline: test (3 Python versions) -> security -> lint -> build
- Build job produces distributable package with twine check
- Codecov integration

### Gaps
- No PyPI publishing step in CI
- Docker image not published to any registry
- No multi-stage Docker build for smaller image
- `docker-compose.yml` uses deprecated `version: '3.8'` key

---

## Dimension 11: Documentation Accuracy (Score: 6)

**Weight: 10%**

### Findings
- README.md: install, generate, verify, signing workflows documented
- QUICKSTART.md, CONTRIBUTING.md, DEPLOYMENT.md, SECURITY.md all present
- CLI help text on all arguments
- Docstrings on all public functions with Args/Returns/Raises

### Gaps
- DEPLOYMENT.md references `SBOM_FORMAT` and `SCAN_VULNERABILITIES` config that don't exist in code
- No API documentation for programmatic use
- No changelog / release notes
- README mentions "Enterprise Tool" but no enterprise features documented

---

## Dimension 12: Domain Capability Depth (Score: 7)

**Weight: 8%**

### Findings
- Core provenance workflow: generate manifest -> sign -> verify (complete chain)
- SHA-256 hashing for file integrity
- Git commit tracking for source provenance
- Glob-based file inclusion patterns
- Metadata key=value pairs for custom annotations
- Deterministic JSON canonicalization for signing
- Recursive directory scanning

### Gaps
- No support for standard SBOM formats (CycloneDX, SPDX) despite "SBOM" in name
- No dependency graph capture
- No model card integration
- No artifact registry integration
- No diffing between manifests

---

## Dimension 13: AI/ML Capability (Score: 5)

**Weight: 5%**

### Findings
- Designed for ML artifact provenance (weights, configs, datasets)
- File-type agnostic (works with any binary or text file)

### Gaps
- No ML-specific features (model card parsing, framework detection, hyperparameter extraction)
- No integration with ML frameworks (PyTorch, TensorFlow, HuggingFace)
- No model lineage tracking

---

## Dimension 14: Connectivity & Channel Interface (Score: 2)

**Weight: 2%**

### Findings
- CLI-only interface
- JSON file I/O for inter-tool communication

### Gaps
- No REST API
- No SDK / library mode (imports not exported)
- No webhook/event integration

---

## Dimension 15-17: UI/UX Dimensions (Score: 0)

**Weight: 0% each -- N/A for CLI tool**

---

## Dimension 18: Zero Trust Architecture (Score: 3)

**Weight: 2%**

### Findings
- File path validation (existence, type, readability checks)
- No network calls except git subprocess

### Gaps
- No input sanitization on metadata values
- No path traversal prevention (relative paths accepted)
- No rate limiting or resource bounds

---

## Dimension 19: Enterprise Security & Compliance (Score: 5)

**Weight: 5%**

### Findings
- MIT license (clear)
- Ed25519 signing for tamper detection
- CI security scanning (bandit + safety)

### Gaps
- No audit logging
- No compliance certifications
- No SBOM for the tool itself
- No vulnerability disclosure process beyond SECURITY.md

---

## Dimension 20: Operational Readiness (Score: 4)

**Weight: 2%**

### Findings
- Docker deployment option available
- CI/CD pipeline functional

### Gaps
- No production deployment evidence
- No runbook or incident response docs
- No backup/recovery procedures
- No SLA documentation

---

## Dimension 21: Agentic Workspace (Score: 2)

**Weight: 2%**

### Findings
- Standalone CLI tool, not an agentic system

### Gaps
- No agent integration
- No MCP/tool-use interface
- Expected for this archetype

---

## Sprint Tasks (Gap Closure)

### Sprint 0 (P0 -- Security)
1. Add Dependabot configuration (.github/dependabot.yml)
2. Set restrictive permissions on private key file writes
3. Add py.typed marker file

### Sprint 1 (Core Gaps)
4. Add `--version` flag to CLI
5. Export public API from `__init__.py` (Manifest, build_manifest, etc.)
6. Add integration tests for full CLI workflows (generate -> sign -> verify)
7. Remove inaccurate DEPLOYMENT.md references to SBOM_FORMAT/SCAN_VULNERABILITIES
8. Add path traversal guards for manifest root resolution

### Sprint 2 (Domain Depth)
9. Add CycloneDX or SPDX output format support
10. Add manifest diff command
11. Add structured JSON logging option
12. Update docker-compose to remove deprecated version key
13. Add PyPI publish step to CI
