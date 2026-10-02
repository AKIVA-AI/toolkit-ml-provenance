"""Sigstore keyless signing and verification for ``sign-file`` / ``verify-file``.

Needs the ``sigstore`` extra (``pip install "toolkit-ml-provenance[sigstore]"``).

Signing produces a Sigstore bundle holding a DSSE envelope over the same
in-toto payload the Ed25519 mode signs (see :mod:`.filesign`). Verification
accepts two bundle kinds:

* DSSE bundles (from ``sign-file --sigstore``, GitHub artifact attestations, or
  any in-toto attestation): the DSSE signature is verified and the payload must
  cover the file.
* Message-signature bundles (from ``sigstore sign <file>``): the signature is
  verified over the file's SHA-256.

Verification always requires the expected signer identity and OIDC issuer; it
never accepts "any identity".
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .filesign import DSSE_PAYLOAD_TYPE, FileVerification, check_binding

MODE = "sigstore"
TOKEN_ENV = "SIGSTORE_ID_TOKEN"  # nosec B105 - environment variable name, not a secret


def _require_sigstore() -> None:
    try:
        import sigstore  # noqa: F401
    except ImportError as exc:
        raise RuntimeError(
            "Sigstore mode needs the 'sigstore' extra: "
            'pip install "toolkit-ml-provenance[sigstore]"'
        ) from exc


def _trust_config(staging: bool) -> Any:
    from sigstore.models import ClientTrustConfig

    return ClientTrustConfig.staging() if staging else ClientTrustConfig.production()


def _identity_token(trust_config: Any, explicit: str | None) -> Any:
    """Find an OIDC identity token: explicit, env, ambient (CI), then interactive."""
    from sigstore.oidc import IdentityToken, Issuer, detect_credential

    raw = explicit or os.environ.get(TOKEN_ENV) or detect_credential()
    if raw:
        return IdentityToken(raw)
    issuer = Issuer(trust_config.signing_config.get_oidc_url())
    return issuer.identity_token()


def sign_payload(
    payload: bytes, *, identity_token: str | None = None, staging: bool = False
) -> str:
    """Sign ``payload`` (an in-toto Statement) keylessly; return the bundle JSON."""
    _require_sigstore()
    from sigstore import dsse
    from sigstore.sign import SigningContext

    trust_config = _trust_config(staging)
    token = _identity_token(trust_config, identity_token)
    ctx = SigningContext.from_trust_config(trust_config)
    statement = dsse.Statement(payload)
    # Keep the default cache=True: with cache=False, sigstore-python 4.x signs
    # with a different ephemeral key than the one in the Fulcio certificate,
    # and Rekor rejects the entry.
    try:
        with ctx.signer(token) as signer:
            bundle = signer.sign_dsse(statement)
    except Exception as exc:  # noqa: BLE001 - surface any Sigstore failure cleanly
        raise RuntimeError(
            f"sigstore signing failed: {type(exc).__name__}: {exc}"
        ) from exc
    return str(bundle.to_json())


def _verifier(staging: bool) -> Any:
    from sigstore.verify import Verifier

    return Verifier.staging() if staging else Verifier.production()


def verify_bundle(
    bundle_bytes: bytes,
    path: Path,
    *,
    identity: str,
    issuer: str,
    staging: bool = False,
    verifier: Any = None,
) -> FileVerification:
    """Verify a Sigstore bundle against the file at ``path``. Fails closed."""
    if not identity or not issuer:
        raise ValueError("sigstore verification needs both an identity and an issuer")
    _require_sigstore()
    from sigstore.hashes import Hashed
    from sigstore.models import Bundle
    from sigstore.verify.policy import Identity
    from sigstore_models.common.v1 import HashAlgorithm

    extra: dict[str, Any] = {"identity": identity, "issuer": issuer}

    def fail(reason: str, sig_ok: bool = False) -> FileVerification:
        return FileVerification(False, reason, MODE, sig_ok, extra=extra)

    try:
        raw = json.loads(bundle_bytes)
        bundle = Bundle.from_json(bundle_bytes)
    except Exception as exc:  # noqa: BLE001 - any parse failure fails closed
        return fail(f"bundle_invalid:{type(exc).__name__}")

    policy = Identity(identity=identity, issuer=issuer)
    verifier = verifier if verifier is not None else _verifier(staging)

    if isinstance(raw, dict) and "dsseEnvelope" in raw:
        extra["bundle_kind"] = "dsse"
        try:
            payload_type, payload = verifier.verify_dsse(bundle, policy)
        except Exception as exc:  # noqa: BLE001
            return fail(f"signature_invalid:{exc}")
        if payload_type != DSSE_PAYLOAD_TYPE:
            return fail("unexpected_payload_type", sig_ok=True)
        binding = check_binding(payload, path)
        return FileVerification(
            ok=binding.ok,
            reason="verified" if binding.ok else binding.reason,
            mode=MODE,
            signature_ok=True,
            binding=binding,
            extra=extra,
        )

    extra["bundle_kind"] = "message_signature"
    from .hashing import sha256_file

    hashed = Hashed(
        algorithm=HashAlgorithm.SHA2_256, digest=bytes.fromhex(sha256_file(path))
    )
    try:
        verifier.verify_artifact(hashed, bundle, policy)
    except Exception as exc:  # noqa: BLE001
        return fail(f"signature_invalid:{exc}")
    return FileVerification(True, "verified", MODE, True, extra=extra)
