from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from .manifest import Manifest, build_manifest
from .signing import canonical_json_bytes, generate_ed25519_keypair, sign_bytes, verify_bytes

logger = logging.getLogger(__name__)

EXIT_SUCCESS = 0
EXIT_CLI_ERROR = 2
EXIT_UNEXPECTED_ERROR = 3
EXIT_VERIFICATION_FAILED = 4


def _parse_meta(items: list[str]) -> dict[str, str]:
    """Parse metadata key=value pairs.
    
    Args:
        items: List of "key=value" strings
        
    Returns:
        Dictionary of metadata
        
    Raises:
        ValueError: If any item is not in key=value format
    """
    out: dict[str, str] = {}
    for it in items:
        if "=" not in it:
            logger.error(f"Invalid metadata format: {it}")
            raise ValueError(f"Metadata must be in key=value format: {it}")
        k, v = it.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def _validate_path_for_read(path: Path) -> Path:
    """Validate path exists and is readable file.
    
    Args:
        path: Path to validate
        
    Returns:
        Resolved absolute path
        
    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If path is not a file
        PermissionError: If file is not readable
    """
    resolved = path.resolve()
    
    if not resolved.exists():
        raise FileNotFoundError(f"File not found: {resolved}")
    
    if not resolved.is_file():
        raise ValueError(f"Path is not a file: {resolved}")
    
    try:
        with resolved.open("r"):
            pass
    except PermissionError as e:
        raise PermissionError(f"File not readable: {resolved}") from e
    
    return resolved


def _validate_path_for_write(path: Path) -> Path:
    """Validate path can be written to.
    
    Args:
        path: Path to validate
        
    Returns:
        Resolved absolute path
        
    Raises:
        ValueError: If path is a directory
    """
    resolved = path.resolve()
    
    if resolved.is_dir():
        raise ValueError(f"Path is a directory, not a file: {resolved}")
    
    parent = resolved.parent
    if parent.exists() and not parent.is_dir():
        raise ValueError(f"Parent path is not a directory: {parent}")
    
    return resolved


def _write(path: Path, obj: object) -> None:
    """Write object to JSON file.
    
    Args:
        path: Path to JSON file
        obj: Object to serialize
        
    Raises:
        ValueError: If object is not JSON serializable
        PermissionError: If path is not writable
        OSError: If file write fails
    """
    validated_path = _validate_path_for_write(path)
    logger.debug(f"Writing JSON to: {validated_path}")
    
    try:
        content = json.dumps(obj, indent=2, sort_keys=True)
    except (TypeError, ValueError) as e:
        logger.error(f"Failed to serialize object: {e}")
        raise ValueError(f"Object is not JSON serializable: {e}") from e
    
    try:
        validated_path.parent.mkdir(parents=True, exist_ok=True)
        validated_path.write_text(content, encoding="utf-8")
        logger.info(f"Wrote JSON to: {validated_path}")
    except (OSError, PermissionError) as e:
        logger.error(f"Failed to write {validated_path}: {e}")
        raise


def _read(path: Path) -> object:
    """Read and parse JSON file.
    
    Args:
        path: Path to JSON file
        
    Returns:
        Parsed JSON data
        
    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If file is not valid JSON
        PermissionError: If file is not readable
    """
    validated_path = _validate_path_for_read(path)
    logger.debug(f"Reading JSON from: {validated_path}")
    
    try:
        content = validated_path.read_text(encoding="utf-8")
        return json.loads(content)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in {validated_path}: {e}")
        raise ValueError(f"Invalid JSON in {validated_path}: {e}") from e
    except (OSError, UnicodeDecodeError) as e:
        logger.error(f"Failed to read {validated_path}: {e}")
        raise


def _cmd_generate(args: argparse.Namespace) -> int:
    """Generate provenance manifest."""
    root = Path(args.root).resolve()
    logger.info(f"Generating manifest for root: {root}")
    
    if not root.exists():
        logger.error(f"Root directory not found: {root}")
        return EXIT_CLI_ERROR
    
    if not root.is_dir():
        logger.error(f"Root is not a directory: {root}")
        return EXIT_CLI_ERROR
    
    paths: list[Path] = []
    for inc in args.include:
        logger.debug(f"Processing include pattern: {inc}")
        matches = list(root.glob(inc))
        if not matches:
            logger.error(f"No files match pattern: {inc}")
            raise ValueError(f"No matches for include pattern: {inc}")
        logger.info(f"Found {len(matches)} files for pattern: {inc}")
        paths.extend(matches)
    
    logger.info(f"Total files to include: {len(paths)}")
    
    try:
        meta = _parse_meta(list(args.meta or []))
        if meta:
            logger.debug(f"Metadata: {meta}")
    except ValueError as e:
        logger.error(f"Invalid metadata: {e}")
        return EXIT_CLI_ERROR
    
    try:
        manifest = build_manifest(root=root, paths=paths, meta=meta)
        logger.info("Manifest generated successfully")
    except Exception as e:
        logger.error(f"Failed to build manifest: {e}")
        return EXIT_CLI_ERROR
    
    try:
        _write(Path(args.out), manifest.to_json())
        return EXIT_SUCCESS
    except (ValueError, OSError, PermissionError) as e:
        logger.error(f"Failed to write manifest: {e}")
        return EXIT_CLI_ERROR


def _cmd_keygen(args: argparse.Namespace) -> int:
    """Generate Ed25519 keypair for signing."""
    private_key_path = Path(args.private_key).resolve()
    public_key_path = Path(args.public_key).resolve()
    
    logger.info("Generating Ed25519 keypair...")
    
    # Check if files already exist
    if private_key_path.exists():
        logger.warning(f"Private key file already exists: {private_key_path}")
    if public_key_path.exists():
        logger.warning(f"Public key file already exists: {public_key_path}")
    
    try:
        kp = generate_ed25519_keypair()
        logger.info("Keypair generated successfully")
    except Exception as e:
        logger.error(f"Failed to generate keypair: {e}")
        return EXIT_CLI_ERROR
    
    try:
        private_key_path.parent.mkdir(parents=True, exist_ok=True)
        private_key_path.write_text(kp.private_key_pem, encoding="utf-8")
        logger.info(f"Wrote private key to: {private_key_path}")
        
        public_key_path.parent.mkdir(parents=True, exist_ok=True)
        public_key_path.write_text(kp.public_key_pem, encoding="utf-8")
        logger.info(f"Wrote public key to: {public_key_path}")
        
        return EXIT_SUCCESS
    except (OSError, PermissionError) as e:
        logger.error(f"Failed to write key files: {e}")
        return EXIT_CLI_ERROR


def _cmd_sign(args: argparse.Namespace) -> int:
    """Sign manifest with private key."""
    manifest_path = Path(args.manifest).resolve()
    private_key_path = Path(args.private_key).resolve()
    
    logger.info(f"Signing manifest: {manifest_path}")
    
    try:
        obj = _read(manifest_path)
        logger.debug("Manifest loaded successfully")
    except (ValueError, FileNotFoundError, PermissionError) as e:
        logger.error(f"Failed to read manifest: {e}")
        return EXIT_CLI_ERROR
    
    try:
        private_pem = _validate_path_for_read(private_key_path).read_text(encoding="utf-8")
        logger.debug("Private key loaded")
    except (FileNotFoundError, PermissionError, UnicodeDecodeError) as e:
        logger.error(f"Failed to read private key: {e}")
        return EXIT_CLI_ERROR
    
    try:
        sig = sign_bytes(payload=canonical_json_bytes(obj), private_key_pem=private_pem)
        logger.info("Manifest signed successfully")
    except Exception as e:
        logger.error(f"Failed to sign manifest: {e}")
        return EXIT_CLI_ERROR
    
    sig_obj = {"algorithm": "ed25519", "signature_b64": sig}
    
    try:
        if args.out:
            _write(Path(args.out), sig_obj)
        else:
            print(json.dumps(sig_obj, indent=2, sort_keys=True))
        return EXIT_SUCCESS
    except (ValueError, OSError, PermissionError) as e:
        logger.error(f"Failed to write signature: {e}")
        return EXIT_CLI_ERROR


def _cmd_verify(args: argparse.Namespace) -> int:
    """Verify manifest against current files."""
    manifest_path = Path(args.manifest).resolve()
    
    logger.info(f"Verifying manifest: {manifest_path}")
    
    try:
        obj = _read(manifest_path)
        m = Manifest.from_json(obj)
        logger.debug("Manifest loaded successfully")
    except (ValueError, FileNotFoundError, PermissionError) as e:
        logger.error(f"Failed to read manifest: {e}")
        return EXIT_CLI_ERROR
    
    root = Path(m.root).resolve()
    logger.info(f"Checking files in root: {root}")
    
    failures: list[dict[str, str]] = []
    
    # Verify file hashes
    for e in m.entries:
        p = root / str(e.get("path") or "")
        if not p.exists() or not p.is_file():
            logger.warning(f"File missing: {e.get('path')}")
            failures.append({"path": str(e.get("path") or ""), "reason": "missing"})
            continue
        
        # lazy import to avoid circulars
        from .hashing import sha256_file
        
        try:
            sha = sha256_file(p)
            if sha != str(e.get("sha256") or ""):
                logger.warning(f"Hash mismatch: {e.get('path')}")
                failures.append({"path": str(e.get("path") or ""), "reason": "hash_mismatch"})
        except Exception as exc:
            logger.error(f"Failed to hash file {e.get('path')}: {exc}")
            failures.append({"path": str(e.get("path") or ""), "reason": f"hash_error:{exc}"})
    
    if not failures:
        logger.info(f"All {len(m.entries)} files verified successfully")
    else:
        logger.error(f"Found {len(failures)} file verification failures")
    
    # Verify signature if provided
    sig_ok = True
    if args.signature and args.public_key:
        logger.info("Verifying signature...")
        
        try:
            sig_obj = _read(Path(args.signature))
            if not isinstance(sig_obj, dict):
                raise ValueError("Signature file must contain a JSON object")
            sig_b64 = str(sig_obj.get("signature_b64") or "")
            
            public_pem = _validate_path_for_read(Path(args.public_key)).read_text(encoding="utf-8")
            
            sig_ok = verify_bytes(
                payload=canonical_json_bytes(m.to_json()),
                signature_b64=sig_b64,
                public_key_pem=public_pem,
            )
            
            if not sig_ok:
                logger.error("Signature verification failed")
                failures.append({"path": "", "reason": "signature_invalid"})
            else:
                logger.info("Signature verified successfully")
                
        except (ValueError, FileNotFoundError, PermissionError) as e:
            logger.error(f"Failed to verify signature: {e}")
            sig_ok = False
            failures.append({"path": "", "reason": f"signature_error:{e}"})
        except Exception as e:
            logger.error(f"Signature verification error: {e}")
            sig_ok = False
            failures.append({"path": "", "reason": f"signature_error:{e}"})
    
    report = {"ok": not failures, "failures": failures, "signature_ok": sig_ok}
    
    try:
        if args.out:
            _write(Path(args.out), report)
        else:
            print(json.dumps(report, indent=2, sort_keys=True))
    except (ValueError, OSError, PermissionError) as e:
        logger.error(f"Failed to write report: {e}")
        return EXIT_CLI_ERROR
    
    if failures:
        logger.error(f"Verification failed with {len(failures)} issues")
        return EXIT_VERIFICATION_FAILED
    else:
        logger.info("Verification passed")
        return EXIT_SUCCESS


def build_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser."""
    p = argparse.ArgumentParser(
        prog="toolkit-mlsbom",
        description=(
            "Toolkit ML Provenance SBOM - Generate and verify"
            " software bill of materials for ML models"
        ),
    )
    p.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging (DEBUG level)",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    gen = sub.add_parser(
        "generate", help="Generate a provenance manifest for the given include globs."
    )
    gen.add_argument(
        "--root", default=".",
        help="Root directory for manifest (default: current dir)",
    )
    gen.add_argument("--out", required=True, help="Output manifest JSON file path")
    gen.add_argument(
        "--include", action="append", default=[],
        required=True, help="Glob pattern for files to include",
    )
    gen.add_argument("--meta", action="append", default=[], help="Metadata in key=value format")
    gen.set_defaults(func=_cmd_generate)

    keygen = sub.add_parser("keygen", help="Generate an Ed25519 keypair for signing manifests.")
    keygen.add_argument("--private-key", required=True, help="Output private key file path")
    keygen.add_argument("--public-key", required=True, help="Output public key file path")
    keygen.set_defaults(func=_cmd_keygen)

    sign = sub.add_parser("sign", help="Sign a manifest and emit a detached signature JSON.")
    sign.add_argument("--manifest", required=True, help="Manifest JSON file path")
    sign.add_argument("--private-key", required=True, help="Private key PEM file path")
    sign.add_argument("--out", default="", help="Output signature file path (default: stdout)")
    sign.set_defaults(func=_cmd_sign)

    ver = sub.add_parser("verify", help="Verify a manifest against current files.")
    ver.add_argument("--manifest", required=True, help="Manifest JSON file path")
    ver.add_argument("--out", default="", help="Output report file path (default: stdout)")
    ver.add_argument("--signature", default="", help="Signature JSON file path (optional)")
    ver.add_argument(
        "--public-key", default="",
        help="Public key PEM file path (required if signature provided)",
    )
    ver.set_defaults(func=_cmd_verify)

    return p


def main(argv: list[str] | None = None) -> int:
    """Main entry point for CLI.
    
    Args:
        argv: Command line arguments (defaults to sys.argv)
        
    Returns:
        Exit code (0 = success, non-zero = error)
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
    )
    
    try:
        return int(args.func(args))
    except (ValueError, FileNotFoundError, PermissionError) as e:
        logger.error(f"{type(e).__name__}: {e}")
        return EXIT_CLI_ERROR
    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        return EXIT_UNEXPECTED_ERROR
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        print(
            "\nAn unexpected error occurred. Please report this issue.",
            file=sys.stderr,
        )
        return EXIT_UNEXPECTED_ERROR


