# toolkit-ml-provenance: guidance for coding agents

CLI `toolkit-mlsbom`, package `toolkit_ml_sbom` (distribution
`toolkit-ml-provenance`). Hashes files into a JSON manifest, optionally
Ed25519-signs it, and verifies files against it. Do not rename the package,
module or CLI.

## Commands

| Command | Purpose |
|---------|---------|
| `pip install -e ".[dev]"` | Install with dev tools |
| `pytest` | Tests |
| `ruff check src/ tests/` | Lint |
| `black --check src/ tests/` | Format check (CI runs it; line length 88) |
| `mypy src/ --ignore-missing-imports` | Type-check (CI) |
| `pyright src/` | Type-check (basic mode) |

## Layout

- `src/toolkit_ml_sbom/cli.py`: argparse CLI (`generate`, `verify`, `keygen`, `sign`,
  `sign-file`, `verify-file`, `sign-model`, `verify-model`, `scan-pickle`)
- `manifest.py`: `Manifest`, `build_manifest`, file expansion and scope
- `envelope.py`: report envelope v1 (in-toto Statement, canonical JSON); schema in `schemas/`
- `filesign.py` / `sigstore_mode.py`: DSSE file signing, Ed25519 and Sigstore (`sigstore` extra)
- `oms.py`: OpenSSF Model Signing (`oms` extra); `importers.py`: `--from-hf` / `--from-mlflow`
- `cyclonedx.py` + `model_info.py`: CycloneDX 1.6 ML-BOM; `pickle_scan.py`: static pickle scan
- `hashing.py`, `signing.py`, `audit_log.py`, `logging_config.py`
- `tests/`: pytest suite, including hypothesis property tests and CLI subprocess tests

## Conventions

- Core is stdlib-only; every integration (`signing`, `sigstore`, `oms`, `hf`, `mlflow`) is an
  optional extra imported lazily, with a clear error when missing.
- ML-BOM output must validate against `tests/schemas/cyclonedx/bom-1.6.schema.json`.
- Tests that need the network skip offline unless `MLSBOM_REQUIRE_NETWORK=1` (the CI extras job).
- Verification fails closed. Never report a check that did not run as passing.
- Manifest paths are relative and POSIX (`/`). The root is stored relative to
  the manifest file. Changing the manifest format needs a `version` bump and
  continued reading of older manifests.
- Exit codes: 0 success, 2 usage/input error, 3 unexpected, 4 verification failed.
- Write a failing test first for every fix, including the negative cases.
