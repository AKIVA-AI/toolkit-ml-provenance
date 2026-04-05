# toolkit-ml-provenance Codebase Map

**Last Updated:** 2026-04-04
**Archetype:** 9 — Developer Tool / CLI
**Package:** `toolkit-ml-provenance-sbom` v0.1.0

---

## Directory Layout

```
toolkit-ml-provenance/
  src/toolkit_ml_sbom/          # Main package (stdlib-only core)
    __init__.py                 # Public API (9 exports)
    __main__.py                 # Module entry point
    cli.py                      # CLI (argparse, 4 subcommands)
    manifest.py                 # Manifest dataclass + builder
    hashing.py                  # SHA-256 file hashing
    signing.py                  # Ed25519 signing (optional cryptography)
    cyclonedx.py                # CycloneDX 1.5 SBOM output
    logging_config.py           # JSON structured logging
    py.typed                    # PEP 561 marker
    control_plane/              # Akiva control-plane adapter
      __init__.py               # Subpackage exports
      config.py                 # 3-tier config hierarchy
      contracts.py              # PermissionScope, ApprovalPolicy, AuthorityBoundary, ToolSpec
      tool_specs.py             # CLI command -> ToolSpec mapping
  tests/
    conftest.py                 # Path setup
    test_manifest.py            # Core manifest + signing tests
    test_hardening.py           # CycloneDX, logging, table, edge cases
    test_enhancements.py        # Path validation, JSON I/O, CLI commands
    test_control_plane.py       # Control-plane contracts + config
  docs/
    CODEBASE_MAP.md             # This file
    audits/                     # Audit reports
  .github/
    workflows/ci.yml            # CI pipeline (test/security/lint/build)
    dependabot.yml              # Dependency updates (pip + actions)
```

## Architecture

```
CLI Layer (cli.py)
  |-- argparse with 4 subcommands: generate, verify, sign, keygen
  |-- Exit codes: 0 (success), 2 (CLI error), 3 (unexpected), 4 (verify failed)
  |-- Structured logging (text or JSON)
  |
Core Layer (stdlib only, zero dependencies)
  |-- manifest.py    Manifest frozen dataclass, build_manifest(), git commit capture
  |-- hashing.py     sha256_file() with 1MB chunk reads
  |-- signing.py     Ed25519 keypair gen, sign, verify (optional cryptography dep)
  |
Output Layer
  |-- cyclonedx.py   Manifest -> CycloneDX 1.5 JSON conversion
  |
Governance Layer (control_plane/)
  |-- contracts.py   PermissionScope, ApprovalPolicy, AuthorityBoundary, ToolSpec
  |-- config.py      3-tier config hierarchy (platform -> toolkit -> CLI)
  |-- tool_specs.py  4 CLI commands mapped to ToolSpecs with schemas
```

## Key Data Flows

### Generate Manifest
```
CLI args -> root + glob patterns -> file discovery -> sha256_file per file
  -> build_manifest() -> Manifest dataclass
  -> [json] _write() to file
  -> [cyclonedx] manifest_to_cyclonedx() -> _write() to file
```

### Sign + Verify
```
Manifest JSON -> canonical_json_bytes() -> sign_bytes(Ed25519) -> sig JSON
Manifest JSON + sig JSON + public key -> verify_bytes() -> bool
```

## Metrics

| Metric | Value |
|--------|-------|
| Source files | 12 |
| Source LOC | ~1,350 |
| Test files | 4 |
| Test functions | 86 |
| Test LOC | ~1,216 |
| Core dependencies | 0 |
| Optional deps | cryptography>=43.0.0 (signing) |
| Python versions | 3.10, 3.11, 3.12 |
| Coverage threshold | 70% (branch) |

## Entry Points

| Entry | Location | Purpose |
|-------|----------|---------|
| `toolkit-mlsbom` | `cli.py:main()` | CLI binary (pip install) |
| `python -m toolkit_ml_sbom` | `__main__.py` | Module execution |
| Python API | `__init__.py` | Programmatic (Manifest, build_manifest, sha256_file, sign/verify) |
