# Toolkit ML Provenance and SBOM

Generates a deterministic JSON manifest (an "ML SBOM") for artifacts like datasets, training configs, code snapshots, and model weights. Supports CycloneDX 1.5 standard SBOM format. Verifies integrity later by re-hashing the referenced artifacts.

## Install

```bash
pip install -e ".[dev]"
```

For signing support:

```bash
pip install -e ".[signing]"
```

## CLI Reference

### Global Options

| Flag | Description |
|------|-------------|
| `--version` | Show version and exit |
| `--verbose`, `-v` | Enable DEBUG-level logging to stderr |
| `--log-format {text,json}` | Log output format (default: text) |

### `generate` -- Create a provenance manifest

```bash
toolkit-mlsbom generate --root <dir> --out <file> --include <glob> [--meta key=value] [--format {json,cyclonedx}]
```

| Argument | Required | Description |
|----------|----------|-------------|
| `--root` | No | Root directory (default: `.`) |
| `--out` | Yes | Output manifest file path |
| `--include` | Yes | Glob pattern for files (repeatable) |
| `--meta` | No | Metadata key=value pair (repeatable) |
| `--format` | No | Output format: `json` (default) or `cyclonedx` (CycloneDX 1.5 JSON) |

**Examples:**

```bash
# Generate manifest for model weights and configs
toolkit-mlsbom generate --root ./my-model \
  --out manifest.json \
  --include "weights/*.safetensors" \
  --include "configs/*.json" \
  --meta model=gpt-2 \
  --meta version=1.0

# Generate CycloneDX SBOM
toolkit-mlsbom generate --root ./my-model \
  --out sbom.cdx.json \
  --include "**/*" \
  --format cyclonedx
```

### `verify` -- Verify file integrity against a manifest

```bash
toolkit-mlsbom verify --manifest <file> [--signature <file> --public-key <file>] [--out <file>] [--format {json,table}]
```

| Argument | Required | Description |
|----------|----------|-------------|
| `--manifest` | Yes | Manifest JSON file path |
| `--signature` | No | Signature JSON file for verification |
| `--public-key` | No | Public key PEM file (required with --signature) |
| `--out` | No | Output report file path (default: stdout) |
| `--format` | No | Output format: `json` (default) or `table` (human-readable) |

**Examples:**

```bash
# Verify manifest
toolkit-mlsbom verify --manifest manifest.json

# Verify with table output
toolkit-mlsbom verify --manifest manifest.json --format table

# Verify with signature
toolkit-mlsbom verify --manifest manifest.json \
  --signature manifest.sig.json \
  --public-key ed25519_pub.pem
```

### `keygen` -- Generate Ed25519 signing keypair

```bash
toolkit-mlsbom keygen --private-key <file> --public-key <file>
```

| Argument | Required | Description |
|----------|----------|-------------|
| `--private-key` | Yes | Output private key file path |
| `--public-key` | Yes | Output public key file path |

### `sign` -- Sign a manifest

```bash
toolkit-mlsbom sign --manifest <file> --private-key <file> [--out <file>]
```

| Argument | Required | Description |
|----------|----------|-------------|
| `--manifest` | Yes | Manifest JSON file path |
| `--private-key` | Yes | Private key PEM file path |
| `--out` | No | Output signature file (default: stdout) |

## Output Formats

### Native JSON (default)

The default `json` format produces a manifest with:

```json
{
  "version": 1,
  "created_ts": 1741500000.0,
  "root": "/path/to/model",
  "git_commit": "abc123...",
  "entries": [
    {"path": "weights/model.bin", "size": 1024, "sha256": "..."}
  ],
  "meta": {"model": "gpt-2"}
}
```

### CycloneDX 1.5 JSON

The `cyclonedx` format produces a [CycloneDX 1.5](https://cyclonedx.org/docs/1.5/json/) compliant SBOM:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:...",
  "version": 1,
  "metadata": {
    "timestamp": "2026-03-09T00:00:00+00:00",
    "tools": {"components": [{"type": "application", "name": "toolkit-ml-provenance-sbom", "version": "0.1.0"}]}
  },
  "components": [
    {"type": "data", "name": "weights/model.bin", "hashes": [{"alg": "SHA-256", "content": "..."}]}
  ]
}
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `2` | Invalid usage / CLI error |
| `3` | Unexpected error |
| `4` | Verification failed |

## Programmatic Usage

The package exports a public Python API:

```python
from toolkit_ml_sbom import (
    Manifest,
    build_manifest,
    sha256_file,
    sign_bytes,
    verify_bytes,
    generate_ed25519_keypair,
    canonical_json_bytes,
)
from pathlib import Path

# Build a manifest
manifest = build_manifest(
    root=Path("./my-model"),
    paths=list(Path("./my-model").glob("**/*")),
    meta={"model": "gpt-2"},
)

# Serialize
data = manifest.to_json()

# Deserialize
loaded = Manifest.from_json(data)
```

## Structured Logging

Enable JSON-formatted logs for log aggregation pipelines:

```bash
toolkit-mlsbom --verbose --log-format json generate --root . --out m.json --include "*.py"
```

Output (stderr):

```json
{"timestamp":"2026-03-09T12:00:00+00:00","level":"INFO","logger":"toolkit_ml_sbom.cli","message":"Generating manifest for root: /path"}
```

## License

MIT License - see LICENSE file for details.
