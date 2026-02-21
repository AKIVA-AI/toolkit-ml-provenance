# ML Provenance & SBOM - Quick Start

## 🚀 Installation

```bash
pip install -e ".[dev]"
toolkit-mlsbom --version
```

## 📝 Basic Usage

```bash
# Generate SBOM
toolkit-mlsbom generate --model models/my-model --out sbom.json

# Scan for vulnerabilities
toolkit-mlsbom scan --sbom sbom.json
```

## 🐳 Docker Usage

```bash
docker-compose up -d
docker-compose exec provenance toolkit-mlsbom generate --model /app/models/my-model
```

## 📚 Next Steps

- Read [README.md](README.md)
- Check [DEPLOYMENT.md](DEPLOYMENT.md)

---

**Ready to secure your ML supply chain!** 🚀
