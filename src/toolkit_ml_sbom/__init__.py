from __future__ import annotations

__version__ = "0.1.0"

from .hashing import sha256_file
from .manifest import Manifest, build_manifest
from .signing import (
    KeyPair,
    canonical_json_bytes,
    generate_ed25519_keypair,
    sign_bytes,
    verify_bytes,
)

__all__ = [
    "__version__",
    "build_manifest",
    "canonical_json_bytes",
    "generate_ed25519_keypair",
    "KeyPair",
    "Manifest",
    "sha256_file",
    "sign_bytes",
    "verify_bytes",
]
