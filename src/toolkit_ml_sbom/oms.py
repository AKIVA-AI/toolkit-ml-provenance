"""OpenSSF Model Signing (OMS) for model directories, via the ``model-signing`` library.

Needs the ``oms`` extra (``pip install "toolkit-ml-provenance[oms]"``).

OMS signs a whole model directory: it hashes every file, puts the per-file
digests in an in-toto Statement, and signs it as a Sigstore bundle (DSSE).
Verification re-hashes the directory and fails on modified, missing or extra
files. Signatures are interoperable with the ``model_signing`` CLI and other
OMS implementations.

Two modes:

* key: an ECDSA private key (P-256, P-384 or P-521; ``keygen --algorithm
  ecdsa-p256``). OMS does not support Ed25519.
* sigstore: keyless, with an OIDC identity, verified against a pinned identity
  and issuer.

The native manifest (``generate`` / ``verify`` / ``sign``) stays the
zero-dependency path.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

OMS_PREDICATE_TYPE = "https://model_signing/signature/v1.0"


def _require_oms() -> Any:
    try:
        import model_signing
    except ImportError as exc:
        raise RuntimeError(
            "OMS model signing needs the 'oms' extra: "
            'pip install "toolkit-ml-provenance[oms]"'
        ) from exc
    return model_signing


def _hashing_config(model_signing: Any, model_dir: Path, signature: Path) -> Any:
    """Default OMS hashing, also ignoring the signature file if it sits inside."""
    config = model_signing.hashing.Config()
    sig, root = signature.resolve(), model_dir.resolve()
    if sig.is_relative_to(root):
        config.add_ignored_paths(model_path=root, paths=[sig.relative_to(root)])
    return config


def sign_model(
    model_dir: Path,
    signature: Path,
    *,
    private_key: Path | None = None,
    sigstore: bool = False,
    identity_token: str | None = None,
    staging: bool = False,
) -> None:
    """Sign ``model_dir`` in OMS format, writing a Sigstore bundle to ``signature``."""
    if (private_key is None) == (not sigstore):
        raise ValueError(
            "choose exactly one OMS signing mode: a private key or sigstore"
        )
    ms = _require_oms()
    config = ms.signing.Config().set_hashing_config(
        _hashing_config(ms, model_dir, signature)
    )
    if private_key is not None:
        config.use_elliptic_key_signer(private_key=private_key)
    else:
        config.use_sigstore_signer(
            identity_token=identity_token,
            use_ambient_credentials=identity_token is None,
            use_staging=staging,
        )
    signature.parent.mkdir(parents=True, exist_ok=True)
    config.sign(model_dir, signature)


@dataclass
class ModelVerification:
    ok: bool
    reason: str
    mode: str
    model_digest: str = ""
    files: list[dict[str, str]] = field(default_factory=list)


def read_oms_statement(signature: Path) -> dict[str, Any]:
    """Decode the in-toto Statement inside an OMS signature (no verification)."""
    bundle = json.loads(signature.read_bytes())
    payload = base64.b64decode(bundle["dsseEnvelope"]["payload"])
    statement = json.loads(payload)
    if not isinstance(statement, dict):
        raise ValueError("oms_payload_not_object")
    return statement


def verify_model(
    model_dir: Path,
    signature: Path,
    *,
    public_key: Path | None = None,
    identity: str = "",
    issuer: str = "",
    staging: bool = False,
) -> ModelVerification:
    """Verify an OMS signature over ``model_dir``. Fails closed on any error."""
    sigstore = bool(identity or issuer)
    if (public_key is None) == (not sigstore):
        raise ValueError(
            "choose exactly one OMS verification mode: a public key, "
            "or an identity with an issuer"
        )
    if sigstore and not (identity and issuer):
        raise ValueError("identity and issuer must be given together")
    ms = _require_oms()
    mode = "sigstore" if sigstore else "ecdsa"
    config = ms.verifying.Config()
    if public_key is not None:
        config.use_elliptic_key_verifier(public_key=public_key)
    else:
        config.use_sigstore_verifier(
            identity=identity, oidc_issuer=issuer, use_staging=staging
        )
    try:
        config.verify(model_dir, signature)
    except Exception as exc:  # noqa: BLE001 - every failure is a failed verification
        return ModelVerification(False, f"{type(exc).__name__}: {exc}", mode)

    statement = read_oms_statement(signature)
    subjects = statement.get("subject") or [{}]
    digest = str((subjects[0].get("digest") or {}).get("sha256", ""))
    predicate = statement.get("predicate") or {}
    files = [
        {"path": str(r.get("name", "")), "sha256": str(r.get("digest", ""))}
        for r in predicate.get("resources", [])
        if isinstance(r, dict)
    ]
    return ModelVerification(True, "verified", mode, digest, files)
