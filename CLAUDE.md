# ML Provenance — Deterministic ML SBOM manifests with CycloneDX support

**Archetype:** 9 — Developer Tool / CLI Utility
**Standards:** See `akiva-enterprise-products/CLAUDE.md` for current Akiva Build Standard version and full standards reference.
**Ontology ID:** TK-06

## Stack

- Language: Python 3.10+
- Test: `pytest -xvs`
- Lint: `ruff check src/ tests/`
- Type-check: `pyright src/` (basic mode)
- Build: `pip install -e ".[dev]"`

## Verification Commands

| Command | Purpose |
|---------|---------|
| `pytest -xvs` | Run tests |
| `pytest --cov=src --cov-report=term-missing` | Run tests with coverage |
| `ruff check src/ tests/` | Lint |
| `pyright src/` | Type-check |
| `mypy src/ --ignore-missing-imports` | Type-check (mypy) |

## Current State

- Audit Score: 75.0/100 (2026-04-04, v2.14 full audit + remediation — prior: 62.9)
- Tests: 100 (5 test files, ~1,550 test LOC)
- Coverage: 81.25% (branch, threshold 70%)
- Source: ~1,450 LOC across 13 modules
- Core dependencies: 0 (stdlib only)

## Key Rules

- Archetype 9: single-purpose CLI tool, zero or minimal dependencies in core
- Tests first, security fixes before features
- One task at a time, verified before moving to next

## Human-Only Actions Required (for 80+)

- **[HUMAN]** Configure GitHub branch protection on `main` (require status checks, no force push)
- **[HUMAN]** Set up PyPI publishing credentials (API token) + first release
- **[HUMAN]** Commission external penetration test / security audit
- **[HUMAN]** Deploy to production environment with real users
- **[HUMAN]** Configure SLSA Level 2 (GitHub Actions OIDC + Sigstore cosign)
