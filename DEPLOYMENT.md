# ML Provenance & SBOM - Deployment Guide

## ðŸš€ Quick Start

### Docker Deployment (Recommended)

```bash
cd toolkit-ml-provenance
docker-compose up -d
docker-compose exec provenance toolkit-mlsbom generate --model models/my-model
```

### Local Installation

```bash
pip install -e ".[dev]"
toolkit-mlsbom --version
pytest
```

## ðŸ”§ Configuration

See `.env.example` for all options.

**Key Settings:**
- `SBOM_FORMAT`: cyclonedx or spdx
- `SCAN_VULNERABILITIES`: Enable vulnerability scanning

## ðŸ“Š Production Deployment

### CI/CD Integration

```yaml
- name: Generate SBOM
  run: toolkit-mlsbom generate --model $MODEL_PATH --out sbom.json
```

## ðŸ”ž Support

- Documentation: [README.md](README.md)
- Support: <support-email>



