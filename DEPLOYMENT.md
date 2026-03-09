# ML Provenance & SBOM - Deployment Guide

## Quick Start

### Docker Deployment (Recommended)

```bash
cd toolkit-ml-provenance
docker-compose up -d
docker-compose exec provenance toolkit-mlsbom generate \
  --root /data/models --out /data/sboms/manifest.json --include "**/*"
```

### Local Installation

```bash
pip install -e ".[dev]"
toolkit-mlsbom --version
pytest
```

## Production Deployment

### CI/CD Integration

```yaml
- name: Generate SBOM
  run: toolkit-mlsbom generate --root $MODEL_PATH --out sbom.json --include "**/*" --format cyclonedx
```

### Output Formats

- `--format json` (default): Internal provenance manifest
- `--format cyclonedx`: CycloneDX 1.5 JSON for compliance toolchains

## Support

- Documentation: [README.md](README.md)
