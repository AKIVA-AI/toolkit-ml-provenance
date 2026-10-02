"""Sign and verify any file with a DSSE envelope over an in-toto Statement.

What gets signed (the DSSE payload, type ``application/vnd.in-toto+json``):

* If the file is itself an in-toto Statement (for example a toolkit report
  envelope), the payload is the file's exact bytes. The signature then covers
  every byte of the report.
* Otherwise the payload is a canonical-JSON Statement whose subject is the
  file's name and SHA-256. The file content is never loaded whole; it is hashed
  in chunks.

Verification fails closed: the signature must verify over the DSSE
pre-authentication encoding (PAE) *and* the payload must cover the file on
disk, either byte-for-byte or through a subject whose SHA-256 matches the file.

Two signing modes share this format:

* ``ed25519``: a local Ed25519 key (``toolkit-mlsbom keygen``), with the
  envelope written as JSON (``<file>.sig.json``).
* ``sigstore``: keyless signing through Sigstore (see :mod:`.sigstore_mode`),
  written as a Sigstore bundle (``<file>.sigstore.json``).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .envelope import STATEMENT_TYPE, TOOL_NAME, canonical_dumps, is_statement
from .hashing import sha256_file

DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
FILE_PREDICATE_TYPE = f"https://github.com/AKIVA-AI/{TOOL_NAME}/file-signature/v1"
ENVELOPE_ALGORITHM = "ed25519"
# Files larger than this are never parsed as JSON; they are always signed by digest.
MAX_STATEMENT_BYTES = 32 * 1024 * 1024


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE v1 pre-authentication encoding.

    ``PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body``
    (https://github.com/secure-systems-lab/dsse/blob/master/protocol.md).
    """
    t = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


def _read_statement_bytes(path: Path) -> bytes | None:
    """Return the file's bytes if it is an in-toto Statement, else None."""
    if path.stat().st_size > MAX_STATEMENT_BYTES:
        return None
    data = path.read_bytes()
    try:
        obj = json.loads(data)
    except (UnicodeDecodeError, ValueError):
        return None
    return data if is_statement(obj) else None


def payload_for_file(path: Path) -> bytes:
    """The DSSE payload that ``sign-file`` signs for ``path``."""
    statement = _read_statement_bytes(path)
    if statement is not None:
        return statement
    return canonical_dumps(
        {
            "_type": STATEMENT_TYPE,
            "subject": [{"name": path.name, "digest": {"sha256": sha256_file(path)}}],
            "predicateType": FILE_PREDICATE_TYPE,
            "predicate": {},
        }
    )


@dataclass
class Binding:
    """How (or whether) a signed payload covers a file."""

    ok: bool
    reason: str
    predicate_type: str = ""
    subjects: list[dict[str, Any]] = field(default_factory=list)


def check_binding(payload: bytes, path: Path) -> Binding:
    """Check that ``payload`` (an in-toto Statement) covers the file at ``path``."""
    try:
        obj = json.loads(payload)
    except (UnicodeDecodeError, ValueError):
        return Binding(False, "payload_not_json")
    if not is_statement(obj):
        return Binding(False, "payload_not_in_toto_statement")
    subjects = [s for s in obj["subject"] if isinstance(s, dict)]
    predicate_type = str(obj.get("predicateType", ""))
    size = path.stat().st_size
    if size == len(payload) and path.read_bytes() == payload:
        return Binding(True, "payload_is_file", predicate_type, subjects)
    digest = sha256_file(path)
    for s in subjects:
        d = s.get("digest")
        if isinstance(d, dict) and d.get("sha256") == digest:
            return Binding(True, "subject_digest_match", predicate_type, subjects)
    return Binding(False, "subject_digest_mismatch", predicate_type, subjects)


def _public_key_id(public_key_pem: str) -> str:
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    der = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def sign_envelope_ed25519(payload: bytes, private_key_pem: str) -> dict[str, Any]:
    """Create a DSSE envelope over ``payload`` with an Ed25519 private key."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
    except ImportError as exc:  # pragma: no cover - depends on install
        raise RuntimeError(f"missing_optional_dep:signing:{exc}") from exc

    key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"), password=None
    )
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("private_key_not_ed25519")
    sig = key.sign(pae(DSSE_PAYLOAD_TYPE, payload))
    public_pem = (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    return {
        "payloadType": DSSE_PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [
            {
                "keyid": _public_key_id(public_pem),
                "sig": base64.b64encode(sig).decode("ascii"),
            }
        ],
    }


@dataclass
class FileVerification:
    ok: bool
    reason: str
    mode: str
    signature_ok: bool
    binding: Binding | None = None
    extra: dict[str, Any] = field(default_factory=dict)


def verify_envelope_ed25519(
    envelope: Any, path: Path, public_key_pem: str
) -> FileVerification:
    """Verify a DSSE envelope made by :func:`sign_envelope_ed25519` against ``path``."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:  # pragma: no cover - depends on install
        raise RuntimeError(f"missing_optional_dep:signing:{exc}") from exc

    def fail(reason: str) -> FileVerification:
        return FileVerification(False, reason, ENVELOPE_ALGORITHM, False)

    if not isinstance(envelope, dict):
        return fail("envelope_not_object")
    if envelope.get("payloadType") != DSSE_PAYLOAD_TYPE:
        return fail("unexpected_payload_type")
    sigs = envelope.get("signatures")
    if not isinstance(sigs, list) or not sigs:
        return fail("no_signatures")
    try:
        payload = base64.b64decode(str(envelope.get("payload", "")), validate=True)
    except (binascii.Error, ValueError):
        return fail("payload_not_base64")

    key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("public_key_not_ed25519")
    message = pae(DSSE_PAYLOAD_TYPE, payload)
    sig_ok = False
    for s in sigs:
        if not isinstance(s, dict):
            continue
        try:
            key.verify(base64.b64decode(str(s.get("sig", "")), validate=True), message)
        except (InvalidSignature, binascii.Error, ValueError):
            continue
        sig_ok = True
        break
    if not sig_ok:
        return fail("signature_invalid")

    binding = check_binding(payload, path)
    return FileVerification(
        ok=binding.ok,
        reason="verified" if binding.ok else binding.reason,
        mode=ENVELOPE_ALGORITHM,
        signature_ok=True,
        binding=binding,
    )
