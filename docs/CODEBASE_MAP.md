# Codebase Map

## Layout

```
toolkit-ml-provenance/
  src/toolkit_ml_sbom/
    __init__.py         Public API exports
    __main__.py         `python -m toolkit_ml_sbom`
    cli.py              argparse CLI: generate, verify, keygen, sign, sign-file, verify-file, sign-model, verify-model, scan-pickle
    manifest.py         Manifest dataclass, build_manifest, expand_files, scope_files
    hashing.py          Streaming SHA-256
    signing.py          Ed25519 keygen/sign/verify (optional cryptography), canonical JSON
    cyclonedx.py        Manifest + ModelInfo -> CycloneDX 1.6 ML-BOM
    model_info.py       ModelInfo; derivation from config.json, model card, requirements
    envelope.py         Report envelope v1 (in-toto Statement, canonical JSON)
    filesign.py         sign-file/verify-file: DSSE + in-toto payloads, Ed25519 mode
    sigstore_mode.py    Sigstore keyless sign/verify (optional `sigstore` extra)
    oms.py              OpenSSF Model Signing wrapper (optional `oms` extra)
    pickle_scan.py      Static unsafe-pickle scanner (pickletools, allow/deny lists)
    importers.py        --from-hf (hf extra) and --from-mlflow run importers
    audit_log.py        Opt-in JSONL audit records (MLSBOM_AUDIT_LOG)
    logging_config.py   JSON log formatter
  schemas/              report-envelope.v1.json (JSON Schema)
  tests/                pytest suite (unit, property-based, CLI subprocess)
  .github/workflows/ci.yml   test / security / lint / build / SBOM jobs
```

## Data flows

### generate

```
--root + --include globs -> glob matches -> expand_files (dedupe, recurse dirs,
drop the output file) -> sha256 per file -> Manifest(root relative to the
manifest file, POSIX entry paths, include globs) -> JSON, or CycloneDX 1.6 ML-BOM (+ derive_model_info)
```

### verify

```
manifest JSON -> root = manifest dir / manifest.root (or --root)
  -> re-hash each entry            -> missing / hash_mismatch
  -> scope_files(root, include)    -> unlisted (fails unless --allow-extra)
  -> optional Ed25519 check over the manifest as read (needs --signature AND --public-key)
  -> report envelope (kind aibom.verify; details {ok, failures, signature_ok, unlisted}); exit 0 / 2 / 4
```

## Entry points

| Entry | Location |
|-------|----------|
| `toolkit-mlsbom` | `cli.py:main()` |
| `python -m toolkit_ml_sbom` | `__main__.py` |
| Python API | `__init__.py` |
