from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class KeyPair:
    private_key_pem: str
    public_key_pem: str


def generate_ed25519_keypair() -> KeyPair:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"missing_optional_dep:signing:{exc}") from exc

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return KeyPair(private_key_pem=private_pem, public_key_pem=public_pem)


def sign_bytes(*, payload: bytes, private_key_pem: str) -> str:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"missing_optional_dep:signing:{exc}") from exc

    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"), password=None
    )
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("private_key_not_ed25519")
    sig = private_key.sign(payload)
    return base64.b64encode(sig).decode("ascii")


def verify_bytes(*, payload: bytes, signature_b64: str, public_key_pem: str) -> bool:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"missing_optional_dep:signing:{exc}") from exc

    public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("public_key_not_ed25519")
    try:
        public_key.verify(base64.b64decode(signature_b64.encode("ascii")), payload)
        return True
    except Exception:
        return False


def canonical_json_bytes(obj: Any) -> bytes:
    """
    Deterministic canonicalization for signing: JSON with sorted keys and compact separators.
    """
    import json

    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
