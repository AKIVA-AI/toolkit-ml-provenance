# Quick Start

## Install (from source)

```bash
git clone https://github.com/AKIVA-AI/toolkit-ml-provenance.git
cd toolkit-ml-provenance
pip install -e ".[signing]"
toolkit-mlsbom --version
```

## Generate a manifest

```bash
# Every file under the model directory
toolkit-mlsbom generate --root ./models --include "**/*" --out manifest.json

# With custom metadata
toolkit-mlsbom generate --root ./models --include "**/*" \
  --meta framework=pytorch --meta version=2.1 --out manifest.json

# CycloneDX 1.6 ML-BOM (for other tools; verify reads the native manifest)
toolkit-mlsbom generate --root ./models --include "**/*" --format cyclonedx --out sbom.cdx.json
```

## Verify

```bash
toolkit-mlsbom verify --manifest manifest.json
toolkit-mlsbom verify --manifest manifest.json --format table
```

`verify` fails on modified, missing and added (unlisted) files. Add
`--allow-extra` to report added files without failing.

## Sign and verify a signature

```bash
toolkit-mlsbom keygen --private-key keys/private.pem --public-key keys/public.pem
toolkit-mlsbom sign --manifest manifest.json --private-key keys/private.pem --out manifest.sig
toolkit-mlsbom verify --manifest manifest.json --signature manifest.sig --public-key keys/public.pem
```

`--signature` and `--public-key` must be given together.

## Docker

```bash
docker compose up -d
docker compose exec provenance toolkit-mlsbom generate \
  --root /app/models --include "**/*" --out /app/sboms/manifest.json
```

## Next steps

- [README.md](README.md): full CLI reference and manifest format
- [DEPLOYMENT.md](DEPLOYMENT.md): CI usage
- [CONTRIBUTING.md](CONTRIBUTING.md): development
