# Toolkit ML Provenance

[![PyPI](https://img.shields.io/pypi/v/toolkit-ml-provenance.svg)](https://pypi.org/project/toolkit-ml-provenance/)
[![Python versions](https://img.shields.io/pypi/pyversions/toolkit-ml-provenance.svg)](https://pypi.org/project/toolkit-ml-provenance/)

`toolkit-mlsbom` is a small command-line tool that records the SHA-256 hash of
every file in an ML artifact set (datasets, configs, code, model weights) into a
JSON manifest, optionally signs that manifest with an Ed25519 key, and later
verifies that the files still match: nothing changed, nothing missing, nothing
added.

It also writes a CycloneDX 1.6 ML-BOM (an AI bill of materials) for the model:
the model and its files with hashes, a model card derived from the files that
ship with it, datasets, base-model lineage and framework packages. For
standard model signatures, `sign-model` / `verify-model` wrap the OpenSSF
Model Signing (OMS) library `model-signing`.

## Five-minute example

An AI-BOM for a small public Hugging Face model, with an unsafe-pickle gate,
a signed report and a later integrity check:

```bash
pip install "toolkit-ml-provenance[hf,signing]"

# 1. Download the model at a pinned commit and write a CycloneDX 1.6 ML-BOM.
#    Fails (exit 4) if a pickle imports something dangerous.
toolkit-mlsbom generate --from-hf hf-internal-testing/tiny-random-gpt2 \
  --hf-revision 71034c5d8bde858ff824298bdedc65515b97d2b9 \
  --hf-allow "*.json" --hf-allow "*.txt" \
  --hf-allow model.safetensors --hf-allow pytorch_model.bin \
  --root ./tiny-gpt2 --out aibom.cdx.json --format cyclonedx \
  --fail-on-pickle dangerous --report aibom-report.json

# 2. Record a manifest to check the files against later.
toolkit-mlsbom generate --root ./tiny-gpt2 --include "**/*" --out manifest.json

# 3. Sign the BOM (any file works, including any toolkit's report envelope).
toolkit-mlsbom keygen --private-key signing.pem --public-key signing.pub
toolkit-mlsbom sign-file aibom.cdx.json --key signing.pem

# 4. Later, or on another machine: check the signature and the files.
toolkit-mlsbom verify-file aibom.cdx.json --public-key signing.pub --format table
toolkit-mlsbom verify --manifest manifest.json --format table
```

`aibom.cdx.json` names the model `pkg:huggingface/hf-internal-testing/tiny-random-gpt2@71034c5...`,
lists every file with its SHA-256, carries the model card derived from
`config.json` (architecture family `gpt2`), and marks
`pytorch_model.bin` as `aibom:pickle-scan: safe`. `aibom-report.json` is a
report envelope (an in-toto Statement) with the counts. Use `--sigstore`
instead of `--key` to sign keylessly, and `sign-model` / `verify-model` for
OpenSSF Model Signing.

## Status

| Capability | Status | Notes |
|---|---|---|
| Manifest of file hashes (`generate`) | Working | Paths are relative and use `/`, so manifests verify on other machines and OSes. |
| Integrity check (`verify`) | Working | Reports modified, missing and **unlisted** (added) files. |
| Ed25519 signing (`keygen`, `sign`, `verify --signature`) | Working | Needs the `signing` extra. Local unencrypted PEM keys only. |
| CycloneDX 1.6 ML-BOM (`generate --format cyclonedx`) | Working | `machine-learning-model` component with model card, files, datasets, base models and packages; validated against the official 1.6 schema in tests. `verify` reads the native manifest, not the BOM. |
| Unsafe-pickle scan (`scan-pickle`, and in `generate`) | Working | Static opcode scan, stdlib only, never unpickles. Raw pickles, PyTorch zip and legacy checkpoints, NumPy object arrays. Cross-checked against `picklescan` in tests. |
| Hugging Face Hub import (`generate --from-hf`) | Working | Needs the `hf` extra. Pins the commit, checks LFS files against the Hub's SHA-256, records repo, commit and model-card data. |
| MLflow run import (`generate --from-mlflow`) | Working | Local file-store run directory (MLflow 2 and 3 layouts): params, final metrics, tags, `MLmodel` flavors and requirements. Flavor details need the `mlflow` extra (PyYAML). Tracking servers and database stores are not read. |
| Model card content | Partial | Only what the model's own files state (`config.json`, `README.md` front matter, `requirements.txt`) plus CLI options. No considerations/fairness sections. |
| SPDX 3 AI profile export | Planned | Not implemented; CycloneDX is the supported AI-BOM format. |
| Git provenance | Partial | Records `HEAD` only; ignores uncommitted changes; not checked by `verify`. |
| Report envelope (`--report`, `verify --out`) | Working | in-toto Statement v1, canonical JSON. See [docs/report-envelope.md](docs/report-envelope.md). |
| Audit log | Working | Opt-in JSONL record per command via `MLSBOM_AUDIT_LOG`. |
| Byte-for-byte reproducible manifests | Not provided | Each manifest carries a creation timestamp; CycloneDX output has a random serial number. |
| Sign any file (`sign-file`, `verify-file`), Ed25519 key | Working | DSSE envelope over an in-toto Statement. Needs the `signing` extra. |
| Sign any file, Sigstore keyless | Working | Needs the `sigstore` extra. Verifies DSSE and message-signature bundles, always against a pinned identity and issuer. |
| OpenSSF Model Signing (`sign-model`, `verify-model`) | Working | Needs the `oms` extra (`model-signing`). ECDSA key or Sigstore keyless. Interoperates with the `model_signing` CLI. |
| Encrypted keys, KMS/HSM | Planned | Not implemented. |
| PyPI package | Working | `pip install toolkit-ml-provenance`; see [Install](#install). |

## Install

Requires Python 3.10+.

```bash
pip install toolkit-ml-provenance                # core, no dependencies
pip install "toolkit-ml-provenance[signing]"     # adds Ed25519 signing (cryptography)
pip install "toolkit-ml-provenance[sigstore]"    # adds Sigstore keyless signing
pip install "toolkit-ml-provenance[oms]"         # adds OpenSSF Model Signing (model-signing)
pip install "toolkit-ml-provenance[hf]"          # adds the Hugging Face Hub importer
pip install "toolkit-ml-provenance[mlflow]"      # adds full MLflow MLmodel parsing (PyYAML)
toolkit-mlsbom --help
```

To work on the code, see [Development](#development).

## How verification works

1. `generate` records, for each file matched by `--include`, its path relative
   to `--root`, its size and its SHA-256. It also records the include globs
   themselves and the root's location relative to the manifest file.
2. `verify` re-hashes every listed file and re-applies the recorded include
   globs. It fails (exit 4) when a file is modified (`hash_mismatch`), missing
   (`missing`) or present inside the include scope but not in the manifest
   (`unlisted`).
3. With `--signature` and `--public-key`, `verify` also checks the Ed25519
   signature over the manifest exactly as stored. Both flags must be given
   together; otherwise `verify` exits 2 instead of skipping the check.

Keep the manifest and signature outside the included files, or pass them to
`verify` so they are not reported as unlisted.

## CLI reference

### Global options

| Flag | Description |
|------|-------------|
| `--version` | Show version and exit |
| `--verbose`, `-v` | Enable DEBUG-level logging to stderr |
| `--log-format {text,json}` | Log output format (default: text) |

### `generate`: create a manifest

```bash
toolkit-mlsbom generate --root <dir> --out <file> --include <glob> [--include <glob> ...] \
  [--meta key=value ...] [--format {json,cyclonedx}] [--report <file>] \
  [--name <n>] [--model-version <v>] [--license <id>] [--base-model <id> ...] \
  [--dataset [name=]<path-or-url> ...] [--requirements <file> ...]
```

| Argument | Required | Description |
|----------|----------|-------------|
| `--root` | No | Root directory (default: `.`) |
| `--out` | Yes | Output file. Never listed in the manifest itself. |
| `--include` | Yes | Glob relative to the root (repeatable). Directories are expanded recursively; each file is listed once. |
| `--meta` | No | Metadata `key=value` pair (repeatable) |
| `--format` | No | `json` (default, the native manifest) or `cyclonedx` (CycloneDX 1.6 ML-BOM) |
| `--report` | No | Also write a report envelope (kind `aibom.generate`) |
| `--name`, `--model-version`, `--license` | No | ML-BOM: model name (default: root directory name), version, license |
| `--base-model` | No | ML-BOM: base model id, e.g. `openai-community/gpt2` (repeatable) |
| `--dataset` | No | ML-BOM: `[name=]path-or-url`; local files and directories are hashed (repeatable) |
| `--requirements` | No | ML-BOM: requirements file for framework and library packages (repeatable) |
| `--no-pickle-scan` | No | Skip the unsafe-pickle scan (on by default) |
| `--fail-on-pickle` | No | `dangerous` or `unknown`: exit 4 (verdict `fail`) when the scan finds such a pickle; outputs are still written |

```bash
# Weights and configs of a model
toolkit-mlsbom generate --root ./my-model --out manifest.json \
  --include "weights/*.safetensors" --include "configs/*.json" \
  --meta model=gpt-2 --meta version=1.0

# Everything under the model directory
toolkit-mlsbom generate --root ./my-model --out manifest.json --include "**/*"

# CycloneDX 1.6 ML-BOM of the same model, with a local training set
toolkit-mlsbom generate --root ./my-model --out aibom.cdx.json --include "**/*" \
  --format cyclonedx --dataset train=./data/train.csv
```

#### Importers

```bash
# A Hugging Face Hub model, downloaded at a pinned commit into an empty directory
toolkit-mlsbom generate --from-hf hf-internal-testing/tiny-random-gpt2 \
  --hf-allow "*.json" --hf-allow "*.safetensors" \
  --root ./tiny --out aibom.cdx.json --format cyclonedx

# A local MLflow run (file store: mlruns/<experiment_id>/<run_id>)
toolkit-mlsbom generate --from-mlflow mlruns/1/0a1b2c... --out aibom.cdx.json --format cyclonedx
```

- `--from-hf REPO_ID` resolves `--hf-revision` (default `main`) to a commit,
  downloads that commit into `--root` (which must be empty), re-hashes every
  LFS file against the SHA-256 the Hub declares (a mismatch is an error), and
  records `purl` `pkg:huggingface/<repo>@<commit>`, the commit as the version,
  and the Hub's model-card data. `--hf-allow` limits the download to matching
  files. `--include` defaults to `**/*`.
- `--from-mlflow RUN_DIR` describes the run's logged model (the first one, or
  `--mlflow-model <name or model id>`): its files become the model's files,
  params become `mlflow:param:*` model-card properties, the latest value of each
  metric becomes a performance metric, and the `MLmodel` flavors and
  `requirements.txt` become framework and library packages. The run id,
  experiment, git commit tag and Python version are recorded as properties.

#### What goes into the ML-BOM

| CycloneDX field | Source |
|---|---|
| `machine-learning-model` component, name / version | root directory name or `--name`; `--model-version` |
| files (nested `file` components, SHA-256, size) | the manifest |
| `licenses` | `license` in the `README.md` front matter (mapped to an SPDX id when known) or `--license` |
| `modelCard.modelParameters.task` | `pipeline_tag` in the front matter |
| `architectureFamily`, `modelArchitecture` | `model_type`, `architectures[0]` in `config.json` |
| `modelParameters.datasets` + `data` components | `datasets` in the front matter (Hugging Face dataset links) and `--dataset` (hashed) |
| `quantitativeAnalysis.performanceMetrics` | `model-index` results in the front matter (needs PyYAML) |
| `pedigree.ancestors` (base-model lineage) | `base_model` in the front matter and `--base-model` |
| `framework` / `library` components (`pkg:pypi`) | `transformers_version` in `config.json`, `library_name`, `requirements.txt` in the root and `--requirements` |
| `dependencies` | model → base models, datasets and packages |
| properties | serialization formats by extension (`safetensors`, `pytorch-pickle`, ...), `aibom:tree-sha256` (digest of the file set), git commit, `--meta` |

The front matter is read with PyYAML when installed (it comes with the `hf`
and `mlflow` extras); otherwise a small built-in parser reads flat keys and
lists and skips nested sections such as `model-index`. Nothing is inferred
beyond what those files state.

### `scan-pickle`: find dangerous pickles

Loading a pickle can run arbitrary code. `scan-pickle` (and `generate`, by
default) reads the opcode stream of every pickle-based file without
unpickling it and classifies each imported global:

- `safe`: on an allowlist of what PyTorch, NumPy and plain containers need
  (`torch._utils._rebuild_tensor_v2`, `collections.OrderedDict`, ...);
- `dangerous`: code execution, file or network access (`os`, `subprocess`,
  `builtins.eval`, `socket`, ...) or an import that cannot be resolved statically;
- `unknown`: anything else.

A file's verdict is its worst import, or `error` if the pickle cannot be
parsed. Formats: raw pickles (`.pkl`, `.pickle`, `.joblib`, and `.bin`/`.pt`
files that start with a pickle header), PyTorch zip checkpoints (each
`*.pkl` member), legacy `torch.save` files (their five pickles), NumPy `.npy`
with object dtype and `.npz`. Safetensors, GGUF, ONNX and raw tensor files
are not pickles and are skipped.

```bash
toolkit-mlsbom scan-pickle ./my-model               # exit 4 on a dangerous import
toolkit-mlsbom scan-pickle --strict ./my-model      # also fail on unknown imports and errors
toolkit-mlsbom generate --root ./my-model --out aibom.cdx.json --include "**/*" \
  --format cyclonedx --fail-on-pickle dangerous
```

`scan-pickle` prints a report envelope of kind `aibom.scan-pickle` whose
`summary` is `{"ok", "policy", "pickle_files", "safe", "unknown", "dangerous",
"error"}` and whose `details.findings` lists each file with its imports. In
the ML-BOM, each scanned file carries `aibom:pickle-scan` (the verdict) and
`aibom:pickle-imports` (the non-safe imports); `generate --report` adds the
same counts under `summary.pickle`.

This is a static check, not a sandbox. It cannot prove a pickle safe when it
imports something off the allowlist (use `--strict` to fail on that), and it
does not look inside compressed joblib files. Prefer safetensors.

### `verify`: check files against a manifest

```bash
toolkit-mlsbom verify --manifest <file> [--root <dir>] [--signature <file> --public-key <file>] \
  [--allow-extra] [--out <file>] [--report <file>] [--format {json,table,legacy-json}]
```

| Argument | Required | Description |
|----------|----------|-------------|
| `--manifest` | Yes | Native JSON manifest. A CycloneDX export is rejected with an explanation. |
| `--root` | No | Directory holding the files (default: the manifest's root, resolved relative to the manifest file) |
| `--signature` | With `--public-key` | Signature JSON from `sign` |
| `--public-key` | With `--signature` | Public key PEM from `keygen` |
| `--allow-extra` | No | Report unlisted files without failing |
| `--out` | No | Write the report envelope to a file as canonical JSON (default: stdout) |
| `--report` | No | Also write the report envelope to a file (useful with `--format table`) |
| `--format` | No | `json` (report envelope, default), `table`, or `legacy-json` (the pre-1.0 report shape, deprecated and removed in 1.1) |

## Report envelope

`verify` output and `generate --report` use the shared toolkit report
envelope: an [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
written as canonical JSON, so any report can be signed and verified with
standard tooling. The format is specified in
[docs/report-envelope.md](docs/report-envelope.md) and
[schemas/report-envelope.v1.json](schemas/report-envelope.v1.json).

- `subject`: the model directory, named after the root and digested as the
  SHA-256 of its canonical sorted entry list (`path`, `sha256`, `size`).
- `predicate.inputs`: the manifest, signature and public key files, by digest.
- `predicate.verdict` / `exit_code`: `pass`/0, `fail`/4, or `error`/2.

`predicate.summary` for `aibom.verify`:

```json
{
  "ok": false,
  "files_checked": 2,
  "missing": 0,
  "hash_mismatch": 0,
  "hash_errors": 0,
  "unlisted": 1,
  "signature": "not_checked"
}
```

`signature` is `ok`, `failed` or `not_checked`. `predicate.details` holds
`failures` (path and reason), `unlisted`, and `signature_ok` (`true`,
`false`, or `null` when no signature was requested).

`predicate.summary` for `aibom.generate` is `{"files", "total_bytes", "format"}`;
`details` names the written output file and its digest.

### `keygen`: create an Ed25519 keypair

```bash
toolkit-mlsbom keygen --private-key <file> --public-key <file> [--force]
```

Refuses to overwrite existing key files unless `--force` is given. The private
key is an unencrypted PKCS#8 PEM created with mode `0600` (on Windows, protect
it with file ACLs instead).

### `sign`: sign a manifest

```bash
toolkit-mlsbom sign --manifest <file> --private-key <file> [--out <file>]
```

Writes a detached signature `{"algorithm": "ed25519", "signature_b64": "..."}`
over the canonical JSON of the manifest (sorted keys, compact separators).

### `sign-file` / `verify-file`: sign any file

These two commands sign and verify any file: a report envelope from any
toolkit, a manifest, a CycloneDX BOM, or a model file. They are the shared
signing path for the toolkit suite.

```bash
# Ed25519 key
toolkit-mlsbom keygen --private-key signing.pem --public-key signing.pub
toolkit-mlsbom sign-file report.json --key signing.pem           # -> report.json.sig.json
toolkit-mlsbom verify-file report.json --public-key signing.pub

# Sigstore keyless (pip install "toolkit-ml-provenance[sigstore]")
toolkit-mlsbom sign-file report.json --sigstore                  # -> report.json.sigstore.json
toolkit-mlsbom verify-file report.json   --identity you@example.com --issuer https://accounts.google.com
```

What is signed is a [DSSE](https://github.com/secure-systems-lab/dsse)
envelope with payload type `application/vnd.in-toto+json`:

- If the file is an in-toto Statement (such as a toolkit report envelope),
  the payload is the file's exact bytes, so any byte change fails verification.
- Any other file is signed through a canonical-JSON in-toto Statement whose
  subject is the file's name and SHA-256 (predicate type
  `https://github.com/AKIVA-AI/toolkit-ml-provenance/file-signature/v1`).
  Large files are hashed in chunks, never loaded whole.

`verify-file` fails closed. It needs exactly one mode: `--public-key`, or
`--identity` together with `--issuer` (there is no "any signer" option). The
signature must verify over the DSSE pre-authentication encoding, and the
payload must cover the file on disk, byte for byte or through a subject
digest. In Sigstore mode it also accepts bundles made by other tools: DSSE
attestations (for example GitHub artifact attestations) and plain
`sigstore sign` message-signature bundles.

`sign-file --sigstore` takes the OIDC token from `--identity-token`,
`$SIGSTORE_ID_TOKEN`, ambient CI credentials (GitHub Actions with
`id-token: write`), or else opens a browser. `--staging` targets Sigstore's
staging instance for testing.

`verify-file` prints a report envelope (kind `aibom.verify-file`) with
`summary` `{"ok", "mode", "signature", "reason"}`, where `mode` is `ed25519`
or `sigstore`, `signature` is `ok` or `failed`, and `reason` is `verified`
or why it failed (`signature_invalid`, `subject_digest_mismatch`,
`unexpected_payload_type`, ...). Use `--report <file>` to also write it to a
file and `--format table` for a short human-readable result.

### `sign-model` / `verify-model`: OpenSSF Model Signing

These wrap [`model-signing`](https://github.com/sigstore/model-transparency),
the reference implementation of the OpenSSF Model Signing (OMS) specification.
The signature is a Sigstore bundle over an in-toto Statement listing every file
in the model directory by SHA-256, so it verifies with the `model_signing` CLI
and other OMS tools, and theirs verify here.

```bash
pip install "toolkit-ml-provenance[oms]"

# ECDSA key (OMS does not support Ed25519)
toolkit-mlsbom keygen --algorithm ecdsa-p256 --private-key ec.pem --public-key ec.pub
toolkit-mlsbom sign-model ./my-model --key ec.pem            # -> my-model.oms.sig
toolkit-mlsbom verify-model ./my-model --public-key ec.pub

# Sigstore keyless
toolkit-mlsbom sign-model ./my-model --sigstore
toolkit-mlsbom verify-model ./my-model \
  --identity you@example.com --issuer https://accounts.google.com
```

`verify-model` fails on any modified, missing or added file (OMS ignores
`.git*` paths and the signature file itself). It prints a report envelope of
kind `aibom.verify-model` whose subject digest is the OMS model digest;
`summary` is `{"ok", "format": "oms", "mode", "files", "reason"}` and
`details.files` lists each signed file and its SHA-256.

The native manifest (`generate`, `verify`, `sign`) remains the
zero-dependency path.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `2` | Invalid usage or input (including `--signature` without `--public-key`) |
| `3` | Unexpected error |
| `4` | Verification failed (including an invalid or unrelated signature) |

## Manifest format

```json
{
  "version": 2,
  "created_ts": 1741500000.0,
  "root": "../my-model",
  "git_commit": "abc123...",
  "include": ["weights/*.safetensors", "configs/*.json"],
  "entries": [
    {"path": "weights/model.safetensors", "size": 1024, "sha256": "..."}
  ],
  "meta": {"model": "gpt-2"}
}
```

- `root` is relative to the directory containing the manifest. Move the model
  and the manifest together, or pass `verify --root`.
- `include` defines the scope checked for unlisted files. Version 1 manifests
  (made before this field existed) have no `include`; `verify` then treats the
  whole root as the scope, so use `--allow-extra` or regenerate them.

## Python API

```python
from pathlib import Path

from toolkit_ml_sbom import Manifest, build_manifest

root = Path("./my-model")
manifest = build_manifest(
    root=root,
    paths=list(root.glob("weights/*")),
    meta={"model": "gpt-2"},
    include=["weights/*"],   # record the scope so verify can detect added files
    manifest_dir=Path("."),  # where the manifest will be written
)
data = manifest.to_json()
loaded = Manifest.from_json(data)
```

Also exported: `sha256_file`, `canonical_json_bytes`, `generate_ed25519_keypair`,
`sign_bytes`, `verify_bytes`, `KeyPair`.

## Logging and audit log

```bash
toolkit-mlsbom --verbose --log-format json generate --root . --out m.json --include "*.py"
```

Set `MLSBOM_AUDIT_LOG=/path/to/audit.jsonl` to append one JSON record per
command (command, arguments without key paths, outcome, duration).

## Development

Install from source in editable mode, with the test, lint and type-check tools:

```bash
git clone https://github.com/AKIVA-AI/toolkit-ml-provenance.git
cd toolkit-ml-provenance
pip install -e ".[dev]" black mypy
pytest
ruff check src/ tests/
black --check src/ tests/
mypy src/ --ignore-missing-imports
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## Contributing and security

Contributions are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md). Please report security problems
privately, as described in [SECURITY.md](SECURITY.md).

## Releasing

Releases are cut by pushing a `vX.Y.Z` tag. CI runs the tests, builds the
sdist and wheel, checks them, attaches them to a GitHub Release and publishes
them to PyPI with Trusted Publishing. [RELEASING.md](RELEASING.md) describes
the process and how to verify a release.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Releases before
the relicensing remain available under the MIT License.
