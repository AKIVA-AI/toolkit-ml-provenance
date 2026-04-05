# ML Provenance & SBOM - Quick Start

## Installation

```bash
pip install -e ".[dev]"
toolkit-mlsbom --version
```

## Generate a Manifest

```bash
# Generate a provenance manifest for all Python files
toolkit-mlsbom generate --root ./src --include "**/*.py" --out manifest.json

# Generate in CycloneDX 1.5 format
toolkit-mlsbom generate --root ./models --include "**/*" --format cyclonedx --out sbom.json

# Add custom metadata
toolkit-mlsbom generate --root ./models --include "**/*" --meta framework=pytorch --meta version=2.1 --out manifest.json
```

## Verify Integrity

```bash
toolkit-mlsbom verify --manifest manifest.json
toolkit-mlsbom verify --manifest manifest.json --format table
```

## Sign and Verify Signatures

```bash
# Generate a keypair
toolkit-mlsbom keygen --private-key keys/private.pem --public-key keys/public.pem

# Sign a manifest
toolkit-mlsbom sign --manifest manifest.json --private-key keys/private.pem --out manifest.sig

# Verify with signature
toolkit-mlsbom verify --manifest manifest.json --signature manifest.sig --public-key keys/public.pem
```

## Docker Usage

```bash
docker-compose up -d
docker-compose exec provenance toolkit-mlsbom generate --root /app/models --include "**/*" --out /app/sboms/manifest.json
```

## Next Steps

- Read [README.md](README.md) for full CLI reference
- Read [DEPLOYMENT.md](DEPLOYMENT.md) for production setup
- Read [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines
