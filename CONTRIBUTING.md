# Contributing to toolkit-ml-provenance

Thanks for helping. For a large change, please open an issue first so we can
agree on the approach.

## Development setup

```bash
git clone https://github.com/AKIVA-AI/toolkit-ml-provenance.git
cd toolkit-ml-provenance
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev,sigstore,oms]"   # the extras let pyright check the optional integrations
```

## Checks

CI runs these on every pull request; run them before you push:

```bash
pytest
ruff check src/ tests/
black --check src/ tests/
pyright
mypy src/ --ignore-missing-imports
```

CI also runs `bandit -r src/`, `pip-audit` with every optional extra installed,
and builds the sdist and wheel (`twine check --strict`).

## Pull requests

1. Branch from `main`.
2. Write a failing test first, then the change. Tests should exercise real
   behavior (real input files, real CLI calls), not only construction.
3. Update the README for user-visible behavior and add a `CHANGELOG.md` entry
   under `[Unreleased]`.
4. Keep the core free of runtime dependencies (stdlib only); optional features go
   in an extra in `pyproject.toml`.
5. Open the pull request against `main` and fill in the template.

## Project conventions

- Keep the manifest format stable. Changes to it need a `version` bump and
  backward-compatible reading of older manifests.
- Verification must fail closed: a check that did not run is never reported as
  passing.
- Cover the negative cases in tests (tampered, missing and added files; bad or
  absent signatures).

## Conduct, security and license

- Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).
- Report security problems privately as described in [SECURITY.md](SECURITY.md),
  not in a public issue.
- Contributions are accepted under the Apache License 2.0 ([LICENSE](LICENSE)):
  by opening a pull request you agree that your contribution is licensed under
  it, as section 5 of the license describes.
- Maintainers: releases are described in [RELEASING.md](RELEASING.md).
