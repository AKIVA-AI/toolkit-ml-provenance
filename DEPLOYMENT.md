# Deployment Guide

`toolkit-mlsbom` is a local command-line tool. There is no server to run.

## Install

From PyPI:

```bash
pip install "toolkit-ml-provenance[signing]"
```

Or build the container image from a clone of the repository:

```bash
docker compose up -d
docker compose exec provenance toolkit-mlsbom --help
```

## CI/CD

Generate and sign a manifest when a model is built, then verify it before the
model is used:

```yaml
- name: Install
  run: pip install "toolkit-ml-provenance[signing]"

- name: Generate and sign manifest
  run: |
    toolkit-mlsbom generate --root "$MODEL_PATH" --include "**/*" --out manifest.json
    toolkit-mlsbom sign --manifest manifest.json --private-key "$SIGNING_KEY_FILE" --out manifest.sig

- name: Verify before deploy
  run: |
    toolkit-mlsbom verify --manifest manifest.json \
      --signature manifest.sig --public-key public.pem
```

`verify` exits non-zero when any file is modified, missing or added, when the
signature is invalid, or when only one of `--signature` / `--public-key` is
given.

Keep the private key out of the repository. The tool reads it from an
unencrypted PEM file; in CI, write it from a secret to a temporary file.

## Output formats

- `--format json` (default): the native manifest, which `verify` reads
- `--format cyclonedx`: a CycloneDX 1.6 ML-BOM for other tools
