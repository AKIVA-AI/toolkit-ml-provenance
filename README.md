# Toolkit ML Provenance and SBOM (Enterprise Tool)

Generates a deterministic JSON manifest (an "ML SBOM") for artifacts like:

- datasets (files or directories)
- training configs
- code snapshots (paths)
- model weights

Then verifies integrity later by re-hashing the referenced artifacts.

## Install

```bash
pip install -e ".[dev]"
```

## Generate

```bash
toolkit-mlsbom generate --root . --out toolkit.mlsbom.json --include configs/*.json --include weights/*.safetensors
```

## Verify

```bash
toolkit-mlsbom verify --manifest toolkit.mlsbom.json
```

## Signing (optional)

Install optional deps:

```bash
pip install -e ".[signing]"
```

Generate keys:

```bash
toolkit-mlsbom keygen --private-key ed25519_priv.pem --public-key ed25519_pub.pem
```

Sign a manifest (detached signature JSON):

```bash
toolkit-mlsbom sign --manifest toolkit.mlsbom.json --private-key ed25519_priv.pem --out toolkit.mlsbom.sig.json
```

Verify including signature:

```bash
toolkit-mlsbom verify --manifest toolkit.mlsbom.json --signature toolkit.mlsbom.sig.json --public-key ed25519_pub.pem
```

Exit codes:

- `0`: pass
- `4`: verification failed
- `2`: invalid usage
- `3`: unexpected error

## License

MIT License - see LICENSE file for details.
