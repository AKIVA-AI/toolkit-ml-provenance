from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

from . import __version__
from .audit_log import configure_audit_log, emit_audit_record
from .cyclonedx import manifest_to_cyclonedx
from .envelope import build_report, file_resource, resource, tree_digest, write_report
from .hashing import sha256_file
from .logging_config import JSONFormatter
from .manifest import Manifest, build_manifest, expand_files, scope_files
from .model_info import (
    ModelInfo,
    derive_model_info,
    local_dataset,
    parse_requirements,
)
from .pickle_scan import (  # nosec B403 - static scanner, never unpickles
    PickleFinding,
    gate_fails,
    scan_file,
    scan_paths,
    summarize,
)
from .signing import (
    canonical_json_bytes,
    generate_ecdsa_p256_keypair,
    generate_ed25519_keypair,
    sign_bytes,
    verify_bytes,
)

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


def _prepare_import(args: argparse.Namespace) -> int:
    """Run the --from-hf / --from-mlflow importers; set args.root and args.include."""
    args.hf_snapshot = None
    args.mlflow_run = None
    args.mlflow_model_dir = None
    if args.from_hf and args.from_mlflow:
        logger.error("use --from-hf or --from-mlflow, not both")
        return EXIT_CLI_ERROR
    if args.from_hf:
        if not args.root:
            logger.error("--from-hf needs --root <empty directory to download into>")
            return EXIT_CLI_ERROR
        from .importers import fetch_hf_model

        try:
            args.hf_snapshot = fetch_hf_model(
                args.from_hf,
                Path(args.root),
                revision=args.hf_revision or None,
                allow_patterns=args.hf_allow or None,
            )
        except Exception as e:  # noqa: BLE001 - network, auth and integrity errors
            logger.error(f"Hugging Face import failed: {type(e).__name__}: {e}")
            return EXIT_CLI_ERROR
    if args.from_mlflow:
        from .importers import read_mlflow_run

        try:
            run = read_mlflow_run(Path(args.from_mlflow))
        except (ValueError, OSError) as e:
            logger.error(f"MLflow import failed: {e}")
            return EXIT_CLI_ERROR
        args.mlflow_run = run
        if args.mlflow_model:
            matches = [
                d
                for d in run.model_dirs
                if args.mlflow_model in (d.name, d.parent.name)
            ]
            if not matches:
                logger.error(f"No logged model named {args.mlflow_model!r} in this run")
                return EXIT_CLI_ERROR
            args.mlflow_model_dir = matches[0]
        elif run.model_dirs:
            args.mlflow_model_dir = run.model_dirs[0]
        if not args.root:
            args.root = str(args.mlflow_model_dir or (run.run_dir / "artifacts"))
    if not args.root:
        args.root = "."
    if not args.include:
        if not (args.from_hf or args.from_mlflow):
            logger.error("give at least one --include glob")
            return EXIT_CLI_ERROR
        args.include = ["**/*"]
    return EXIT_SUCCESS


def _cmd_generate(args: argparse.Namespace) -> int:
    """Generate provenance manifest."""
    rc = _prepare_import(args)
    if rc != EXIT_SUCCESS:
        return rc
    root = Path(args.root).resolve()
    logger.info(f"Generating manifest for root: {root}")

    if not root.exists():
        logger.error(f"Root directory not found: {root}")
        return EXIT_CLI_ERROR

    if not root.is_dir():
        logger.error(f"Root is not a directory: {root}")
        return EXIT_CLI_ERROR

    out_path = Path(args.out).resolve()
    report_path = Path(args.report).resolve() if args.report else None
    # Store globs with "/" so the recorded scope works on every OS.
    include = [
        inc.replace("\\", "/") if os.sep == "\\" else inc for inc in args.include
    ]
    paths: list[Path] = []
    for inc in include:
        logger.debug(f"Processing include pattern: {inc}")
        matches = list(root.glob(inc))
        if not matches:
            logger.error(f"No files match pattern: {inc}")
            raise ValueError(f"No matches for include pattern: {inc}")
        logger.info(f"Found {len(matches)} files for pattern: {inc}")
        paths.extend(matches)

    # Never list the manifest or report (they may sit inside an included directory).
    paths = [f for f in expand_files(paths) if f not in (out_path, report_path)]
    logger.info(f"Total files to include: {len(paths)}")

    try:
        meta = _parse_meta(list(args.meta or []))
        if meta:
            logger.debug(f"Metadata: {meta}")
    except ValueError as e:
        logger.error(f"Invalid metadata: {e}")
        return EXIT_CLI_ERROR

    try:
        manifest = build_manifest(
            root=root,
            paths=paths,
            meta=meta,
            manifest_dir=out_path.parent,
            include=include,
        )
        logger.info("Manifest generated successfully")
    except Exception as e:
        logger.error(f"Failed to build manifest: {e}")
        return EXIT_CLI_ERROR

    findings: list[PickleFinding] = []
    if not args.no_pickle_scan:
        findings = scan_paths(root, [str(e["path"]) for e in manifest.entries])
        for f in findings:
            if f.verdict != "safe":
                logger.warning(f"Pickle scan: {f.path} is {f.verdict}")

    try:
        fmt = getattr(args, "format", "json")
        if fmt == "cyclonedx":
            info = _model_info_for(args, root, manifest)
            for f in findings:
                props = {"aibom:pickle-scan": f.verdict}
                risky = [
                    f"{g['module']}.{g['name']}"
                    for g in f.globals
                    if g["safety"] != "safe"
                ]
                if risky:
                    props["aibom:pickle-imports"] = ",".join(risky)
                info.file_properties[f.path] = props
            cdx = manifest_to_cyclonedx(manifest, tool_version=__version__, model=info)
            _write(Path(args.out), cdx)
        else:
            _write(Path(args.out), manifest.to_json())
    except (ValueError, OSError, PermissionError) as e:
        logger.error(f"Failed to write manifest: {e}")
        return EXIT_CLI_ERROR

    gate_failed = bool(args.fail_on_pickle) and gate_fails(
        findings, args.fail_on_pickle
    )
    exit_code = EXIT_VERIFICATION_FAILED if gate_failed else EXIT_SUCCESS
    if gate_failed:
        logger.error(
            f"Pickle gate ({args.fail_on_pickle}) failed: "
            + ", ".join(f.path for f in findings if f.verdict != "safe")
        )

    if report_path is not None:
        report = build_report(
            kind="aibom.generate",
            verdict="fail" if gate_failed else "pass",
            exit_code=exit_code,
            subject=[resource(root.name or str(root), tree_digest(manifest.entries))],
            summary={
                "files": len(manifest.entries),
                "total_bytes": sum(int(e.get("size", 0)) for e in manifest.entries),
                "format": fmt,
                "pickle": (
                    summarize(findings) if not args.no_pickle_scan else "not_scanned"
                ),
            },
            details={
                "output": file_resource(out_path),
                "include": list(include),
                "git_commit": manifest.git_commit,
                "pickle_findings": [f.to_json() for f in findings],
                "pickle_policy": args.fail_on_pickle or "report",
            },
        )
        try:
            write_report(report_path, report)
        except OSError as e:
            logger.error(f"Failed to write report: {e}")
            return EXIT_CLI_ERROR
    return exit_code


def _model_info_for(
    args: argparse.Namespace, root: Path, manifest: Manifest
) -> ModelInfo:
    """Derive the ML-BOM model description, then apply command-line additions."""
    default_name = None
    if getattr(args, "hf_snapshot", None) is not None:
        default_name = args.hf_snapshot.repo_id.rsplit("/", 1)[-1]
    elif getattr(args, "mlflow_run", None) is not None:
        default_name = str(
            args.mlflow_run.meta.get("run_name") or args.mlflow_run.run_dir.name
        )
    info = derive_model_info(root, manifest.entries, name=args.name or default_name)
    if getattr(args, "hf_snapshot", None) is not None:
        from .importers import apply_hf_snapshot

        apply_hf_snapshot(info, args.hf_snapshot)
    if getattr(args, "mlflow_run", None) is not None:
        from .importers import apply_mlflow_run

        apply_mlflow_run(info, args.mlflow_run, args.mlflow_model_dir)
    if args.model_version:
        info.version = args.model_version
    if args.license:
        info.license = args.license
    for base in args.base_model:
        if base not in info.base_models:
            info.base_models.append(base)
    for spec in args.dataset:
        info.add_dataset(local_dataset(spec))
    for req in args.requirements:
        path = _validate_path_for_read(Path(req))
        for pkg in parse_requirements(path.read_text(encoding="utf-8"), path.name):
            info.add_package(pkg)
    return info


def _write_private(path: Path, text: str) -> None:
    """Write ``text`` to ``path``, creating it owner-read/write only (0o600).

    The mode is set when the file is created, so the key is never readable by
    others, even briefly. On Windows the mode bits have no effect; protect the
    key with filesystem ACLs.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    try:
        path.chmod(0o600)  # also tighten a pre-existing file replaced via --force
    except OSError:
        logger.warning(f"Could not set restrictive permissions on {path}")


def _cmd_keygen(args: argparse.Namespace) -> int:
    """Generate Ed25519 keypair for signing."""
    private_key_path = Path(args.private_key).resolve()
    public_key_path = Path(args.public_key).resolve()

    algorithm = getattr(args, "algorithm", "ed25519")
    logger.info(f"Generating {algorithm} keypair...")

    # Never destroy an existing signing identity without an explicit --force.
    existing = [p for p in (private_key_path, public_key_path) if p.exists()]
    if existing and not args.force:
        for p in existing:
            logger.error(f"Key file already exists: {p} (use --force to overwrite)")
        return EXIT_CLI_ERROR

    try:
        kp = (
            generate_ecdsa_p256_keypair()
            if algorithm == "ecdsa-p256"
            else generate_ed25519_keypair()
        )
        logger.info("Keypair generated successfully")
    except Exception as e:
        logger.error(f"Failed to generate keypair: {e}")
        return EXIT_CLI_ERROR

    try:
        private_key_path.parent.mkdir(parents=True, exist_ok=True)
        _write_private(private_key_path, kp.private_key_pem)
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
        private_pem = _validate_path_for_read(private_key_path).read_text(
            encoding="utf-8"
        )
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


def _format_table(report: dict[str, object]) -> str:
    """Format verification report as a human-readable table.

    Args:
        report: Verification report dictionary.

    Returns:
        Formatted table string.
    """
    lines: list[str] = []
    ok = report.get("ok", False)
    sig_ok = report.get("signature_ok")
    failures = report.get("failures", [])

    if sig_ok is None:
        sig_label = "NOT CHECKED"
    else:
        sig_label = "OK" if sig_ok else "FAILED"
    lines.append(f"Status: {'PASS' if ok else 'FAIL'}")
    lines.append(f"Signature: {sig_label}")

    if isinstance(failures, list) and failures:
        lines.append("")
        lines.append(f"{'Path':<50} {'Reason':<20}")
        lines.append("-" * 70)
        for f in failures:
            if isinstance(f, dict):
                path = str(f.get("path", ""))
                reason = str(f.get("reason", ""))
                lines.append(f"{path:<50} {reason:<20}")
    elif ok:
        lines.append("All files verified successfully.")

    return "\n".join(lines)


def _cmd_verify(args: argparse.Namespace) -> int:
    """Verify manifest against current files."""
    manifest_path = Path(args.manifest).resolve()

    # Fail closed: a signature check is either fully specified or not requested.
    if bool(args.signature) != bool(args.public_key):
        logger.error(
            "--signature and --public-key must be given together; "
            "refusing to report a signature check that did not run"
        )
        return EXIT_CLI_ERROR

    logger.info(f"Verifying manifest: {manifest_path}")

    try:
        obj = _read(manifest_path)
        if isinstance(obj, dict) and obj.get("bomFormat") == "CycloneDX":
            raise ValueError(
                "this is a CycloneDX export, which verify does not read; "
                "verify the native JSON manifest (generate --format json)"
            )
        m = Manifest.from_json(obj)
        logger.debug("Manifest loaded successfully")
    except (ValueError, FileNotFoundError, PermissionError) as e:
        logger.error(f"Failed to read manifest: {e}")
        if args.report and manifest_path.is_file():
            try:
                write_report(
                    Path(args.report),
                    _error_envelope("aibom.verify", manifest_path, str(e)),
                )
            except OSError as werr:
                logger.error(f"Failed to write report: {werr}")
        return EXIT_CLI_ERROR

    # The stored root is relative to the manifest file (older manifests may hold
    # an absolute path, which the join below leaves unchanged).
    if getattr(args, "root", ""):
        root = Path(args.root).resolve()
    else:
        root = (manifest_path.parent / m.root).resolve()
    logger.info(f"Checking files in root: {root}")

    failures: list[dict[str, str]] = []

    # Verify file hashes
    for entry in m.entries:
        p = root / str(entry.get("path") or "")
        if not p.exists() or not p.is_file():
            logger.warning(f"File missing: {entry.get('path')}")
            failures.append({"path": str(entry.get("path") or ""), "reason": "missing"})
            continue

        # lazy import to avoid circulars
        from .hashing import sha256_file

        try:
            sha = sha256_file(p)
            if sha != str(entry.get("sha256") or ""):
                logger.warning(f"Hash mismatch: {entry.get('path')}")
                failures.append(
                    {"path": str(entry.get("path") or ""), "reason": "hash_mismatch"}
                )
        except Exception as exc:
            logger.error(f"Failed to hash file {entry.get('path')}: {exc}")
            failures.append(
                {"path": str(entry.get("path") or ""), "reason": f"hash_error:{exc}"}
            )

    # Detect files inside the manifest's scope that the manifest does not list.
    listed = {str(entry.get("path") or "") for entry in m.entries}
    own_files = {
        Path(p).resolve()
        for p in (args.manifest, args.signature, args.public_key, args.out, args.report)
        if p
    }
    unlisted: list[str] = []
    if root.is_dir():
        for f in scope_files(root, m.include):
            rel = f.relative_to(root).as_posix()
            if f not in own_files and rel not in listed:
                unlisted.append(rel)
    unlisted.sort()
    for rel in unlisted:
        logger.warning(f"File not listed in manifest: {rel}")
        if not args.allow_extra:
            failures.append({"path": rel, "reason": "unlisted"})

    if not failures:
        logger.info(f"All {len(m.entries)} files verified successfully")
    else:
        logger.error(f"Found {len(failures)} file verification failures")

    # Verify signature if provided. None means "not checked", never "passed".
    sig_ok: bool | None = None
    if args.signature and args.public_key:
        logger.info("Verifying signature...")

        try:
            sig_obj = _read(Path(args.signature))
            if not isinstance(sig_obj, dict):
                raise ValueError("Signature file must contain a JSON object")
            sig_b64 = str(sig_obj.get("signature_b64") or "")

            public_pem = _validate_path_for_read(Path(args.public_key)).read_text(
                encoding="utf-8"
            )

            # Verify over the manifest exactly as read, so every field is covered.
            sig_ok = verify_bytes(
                payload=canonical_json_bytes(obj),
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

    report = {
        "ok": not failures,
        "failures": failures,
        "signature_ok": sig_ok,
        "unlisted": unlisted,
    }
    exit_code = EXIT_VERIFICATION_FAILED if failures else EXIT_SUCCESS
    if failures:
        logger.error(f"Verification failed with {len(failures)} issues")
    else:
        logger.info("Verification passed")

    envelope = _verify_envelope(args, m, root, failures, unlisted, sig_ok, exit_code)

    try:
        fmt = getattr(args, "format", "json")
        if args.report:
            write_report(Path(args.report), envelope)
        if fmt == "legacy-json":
            if args.out:
                _write(Path(args.out), report)
            else:
                print(json.dumps(report, indent=2, sort_keys=True))
        elif args.out:
            write_report(Path(args.out), envelope)
        elif fmt == "table":
            print(_format_table(report))
        else:
            print(json.dumps(envelope, indent=2, sort_keys=True))
    except (ValueError, OSError, PermissionError) as e:
        logger.error(f"Failed to write report: {e}")
        return EXIT_CLI_ERROR

    return exit_code


def _verify_envelope(
    args: argparse.Namespace,
    m: Manifest,
    root: Path,
    failures: list[dict[str, str]],
    unlisted: list[str],
    sig_ok: bool | None,
    exit_code: int,
) -> dict[str, Any]:
    """Wrap a verify result in the toolkit report envelope (kind aibom.verify)."""

    def count(reason: str) -> int:
        return sum(1 for f in failures if f.get("reason", "").startswith(reason))

    signature = "not_checked" if sig_ok is None else ("ok" if sig_ok else "failed")
    inputs = [file_resource(Path(args.manifest))]
    for extra in (args.signature, args.public_key):
        if extra and Path(extra).is_file():
            inputs.append(file_resource(Path(extra)))
    return build_report(
        kind="aibom.verify",
        verdict="pass" if exit_code == EXIT_SUCCESS else "fail",
        exit_code=exit_code,
        subject=[resource(root.name or str(root), tree_digest(m.entries))],
        inputs=inputs,
        summary={
            "ok": not failures,
            "files_checked": len(m.entries),
            "missing": count("missing"),
            "hash_mismatch": count("hash_mismatch"),
            "hash_errors": count("hash_error"),
            "unlisted": len(unlisted),
            "signature": signature,
        },
        details={
            "ok": not failures,
            "failures": failures,
            "signature_ok": sig_ok,
            "unlisted": unlisted,
        },
    )


def _error_envelope(kind: str, subject_path: Path, message: str) -> dict[str, Any]:
    """A report envelope for a run that could not judge its input (verdict error)."""
    return build_report(
        kind=kind,
        verdict="error",
        exit_code=EXIT_CLI_ERROR,
        subject=[file_resource(subject_path)],
        inputs=[file_resource(subject_path)],
        summary={"ok": False, "error": message},
        details={"error": message},
    )


def _default_signature_path(path: Path, sigstore: bool) -> Path:
    suffix = ".sigstore.json" if sigstore else ".sig.json"
    return path.with_name(path.name + suffix)


def _cmd_sign_file(args: argparse.Namespace) -> int:
    """Sign any file: DSSE envelope over an in-toto Statement."""
    from .filesign import payload_for_file, sign_envelope_ed25519

    if bool(args.key) == bool(args.sigstore):
        logger.error(
            "choose exactly one signing mode: --key <private.pem> or --sigstore"
        )
        return EXIT_CLI_ERROR
    try:
        path = _validate_path_for_read(Path(args.file))
    except (FileNotFoundError, ValueError, PermissionError) as e:
        logger.error(str(e))
        return EXIT_CLI_ERROR
    out = (
        Path(args.out)
        if args.out
        else _default_signature_path(Path(args.file), bool(args.sigstore))
    )

    payload = payload_for_file(path)
    try:
        if args.sigstore:
            from .sigstore_mode import sign_payload

            text = sign_payload(
                payload,
                identity_token=args.identity_token or None,
                staging=args.staging,
            )
        else:
            private_pem = _validate_path_for_read(Path(args.key)).read_text(
                encoding="utf-8"
            )
            text = json.dumps(
                sign_envelope_ed25519(payload, private_pem), indent=2, sort_keys=True
            )
    except Exception as e:  # noqa: BLE001 - OIDC/Fulcio/Rekor errors are not bugs
        logger.error(f"Signing failed: {type(e).__name__}: {e}")
        return EXIT_CLI_ERROR

    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text + "\n", encoding="utf-8")
    except OSError as e:
        logger.error(f"Failed to write signature: {e}")
        return EXIT_CLI_ERROR
    print(str(out))
    return EXIT_SUCCESS


def _cmd_verify_file(args: argparse.Namespace) -> int:
    """Verify a file against a signature from sign-file (or a Sigstore bundle)."""
    from .filesign import FileVerification, verify_envelope_ed25519

    key_mode = bool(args.public_key)
    sigstore_mode = bool(args.identity or args.issuer)
    if key_mode == sigstore_mode:
        logger.error(
            "choose exactly one verification mode: --public-key <pem>, or "
            "--identity <signer> with --issuer <oidc-issuer-url>"
        )
        return EXIT_CLI_ERROR
    if sigstore_mode and not (args.identity and args.issuer):
        logger.error("--identity and --issuer must be given together")
        return EXIT_CLI_ERROR

    try:
        path = _validate_path_for_read(Path(args.file))
        sig_path = _validate_path_for_read(
            Path(args.signature)
            if args.signature
            else _default_signature_path(Path(args.file), sigstore_mode)
        )
        sig_bytes = sig_path.read_bytes()
        public_pem = (
            _validate_path_for_read(Path(args.public_key)).read_text(encoding="utf-8")
            if key_mode
            else ""
        )
    except (FileNotFoundError, ValueError, PermissionError, OSError) as e:
        logger.error(str(e))
        return EXIT_CLI_ERROR

    try:
        if key_mode:
            try:
                envelope = json.loads(sig_bytes)
            except ValueError:
                envelope = None
            result: FileVerification = verify_envelope_ed25519(
                envelope, path, public_pem
            )
        else:
            from .sigstore_mode import verify_bundle

            result = verify_bundle(
                sig_bytes,
                path,
                identity=args.identity,
                issuer=args.issuer,
                staging=args.staging,
            )
    except (ValueError, RuntimeError) as e:
        logger.error(f"Cannot verify: {e}")
        return EXIT_CLI_ERROR

    exit_code = EXIT_SUCCESS if result.ok else EXIT_VERIFICATION_FAILED
    inputs = [file_resource(sig_path)]
    if key_mode:
        inputs.append(file_resource(Path(args.public_key)))
    details: dict[str, Any] = {"reason": result.reason, **result.extra}
    if result.binding is not None:
        details["binding"] = result.binding.reason
        details["predicate_type"] = result.binding.predicate_type
        details["signed_subjects"] = result.binding.subjects
    report = build_report(
        kind="aibom.verify-file",
        verdict="pass" if result.ok else "fail",
        exit_code=exit_code,
        subject=[file_resource(path)],
        inputs=inputs,
        summary={
            "ok": result.ok,
            "mode": result.mode,
            "signature": "ok" if result.signature_ok else "failed",
            "reason": result.reason,
        },
        details=details,
    )
    if result.ok:
        logger.info(f"Verified {path.name}: {result.reason}")
    else:
        logger.error(f"Verification failed for {path.name}: {result.reason}")

    try:
        if args.report:
            write_report(Path(args.report), report)
        if args.format == "table":
            print(f"Status: {'PASS' if result.ok else 'FAIL'}")
            print(f"Mode: {result.mode}")
            print(f"Reason: {result.reason}")
        else:
            print(json.dumps(report, indent=2, sort_keys=True))
    except OSError as e:
        logger.error(f"Failed to write report: {e}")
        return EXIT_CLI_ERROR
    return exit_code


def _default_model_signature(model_dir: Path) -> Path:
    resolved = model_dir.resolve()
    return resolved.with_name(resolved.name + ".oms.sig")


def _cmd_sign_model(args: argparse.Namespace) -> int:
    """Sign a model directory in OpenSSF Model Signing (OMS) format."""
    from .oms import sign_model

    model_dir = Path(args.model_dir)
    if not model_dir.is_dir():
        logger.error(f"Not a directory: {model_dir}")
        return EXIT_CLI_ERROR
    if bool(args.key) == bool(args.sigstore):
        logger.error(
            "choose exactly one signing mode: --key <ec-private.pem> or --sigstore"
        )
        return EXIT_CLI_ERROR
    out = Path(args.out) if args.out else _default_model_signature(model_dir)
    try:
        sign_model(
            model_dir,
            out,
            private_key=Path(args.key) if args.key else None,
            sigstore=args.sigstore,
            identity_token=args.identity_token or None,
            staging=args.staging,
        )
    except Exception as e:  # noqa: BLE001 - key, OIDC and Sigstore errors alike
        logger.error(f"OMS signing failed: {type(e).__name__}: {e}")
        return EXIT_CLI_ERROR
    print(str(out))
    return EXIT_SUCCESS


def _cmd_verify_model(args: argparse.Namespace) -> int:
    """Verify an OMS signature over a model directory."""
    from .oms import verify_model

    model_dir = Path(args.model_dir)
    if not model_dir.is_dir():
        logger.error(f"Not a directory: {model_dir}")
        return EXIT_CLI_ERROR
    sig_path = (
        Path(args.signature) if args.signature else _default_model_signature(model_dir)
    )
    if not sig_path.is_file():
        logger.error(f"Signature not found: {sig_path}")
        return EXIT_CLI_ERROR
    try:
        result = verify_model(
            model_dir,
            sig_path,
            public_key=Path(args.public_key) if args.public_key else None,
            identity=args.identity,
            issuer=args.issuer,
            staging=args.staging,
        )
    except (ValueError, RuntimeError) as e:
        logger.error(f"Cannot verify: {e}")
        return EXIT_CLI_ERROR

    exit_code = EXIT_SUCCESS if result.ok else EXIT_VERIFICATION_FAILED
    subject_name = model_dir.resolve().name
    subject_digest = result.model_digest or file_resource(sig_path)["digest"]["sha256"]
    inputs = [file_resource(sig_path)]
    if args.public_key:
        inputs.append(file_resource(Path(args.public_key)))
    report = build_report(
        kind="aibom.verify-model",
        verdict="pass" if result.ok else "fail",
        exit_code=exit_code,
        subject=[resource(subject_name, subject_digest)],
        inputs=inputs,
        summary={
            "ok": result.ok,
            "format": "oms",
            "mode": result.mode,
            "files": len(result.files),
            "reason": "verified" if result.ok else "signature_mismatch",
        },
        details={
            "reason": result.reason,
            "files": result.files,
            "identity": args.identity,
            "issuer": args.issuer,
        },
    )
    if result.ok:
        logger.info(f"OMS signature verified for {subject_name}")
    else:
        logger.error(f"OMS verification failed: {result.reason}")
    try:
        if args.report:
            write_report(Path(args.report), report)
        if args.format == "table":
            print(f"Status: {'PASS' if result.ok else 'FAIL'}")
            print(f"Reason: {result.reason}")
        else:
            print(json.dumps(report, indent=2, sort_keys=True))
    except OSError as e:
        logger.error(f"Failed to write report: {e}")
        return EXIT_CLI_ERROR
    return exit_code


def _cmd_scan_pickle(args: argparse.Namespace) -> int:
    """Statically scan pickle-based files for dangerous imports."""
    findings: list[PickleFinding] = []
    subjects: list[dict[str, Any]] = []
    for raw in args.paths:
        path = Path(raw)
        if path.is_file():
            subjects.append(file_resource(path))
            finding = scan_file(path, path.name)
            if finding is not None:
                findings.append(finding)
        elif path.is_dir():
            root = path.resolve()
            files = [f for f in expand_files([root]) if f.is_file()]
            rels = [f.relative_to(root).as_posix() for f in files]
            entries = [
                {"path": rel, "sha256": sha256_file(f), "size": f.stat().st_size}
                for rel, f in zip(rels, files, strict=True)
            ]
            subjects.append(resource(root.name or str(root), tree_digest(entries)))
            findings.extend(scan_paths(root, rels))
        else:
            logger.error(f"Not found: {path}")
            return EXIT_CLI_ERROR

    policy = "unknown" if args.strict else "dangerous"
    failed = gate_fails(findings, policy)
    exit_code = EXIT_VERIFICATION_FAILED if failed else EXIT_SUCCESS
    counts = summarize(findings)
    report = build_report(
        kind="aibom.scan-pickle",
        verdict="fail" if failed else "pass",
        exit_code=exit_code,
        subject=subjects,
        summary={"ok": not failed, "policy": policy, **counts},
        details={"findings": [f.to_json() for f in findings]},
    )
    try:
        if args.report:
            write_report(Path(args.report), report)
        if args.format == "table":
            print(f"Status: {'PASS' if not failed else 'FAIL'} (policy: {policy})")
            for f in findings:
                risky = [
                    f"{g['module']}.{g['name']}"
                    for g in f.globals
                    if g["safety"] != "safe"
                ]
                print(f"{f.verdict:<10} {f.path}  {' '.join(risky)}".rstrip())
        else:
            print(json.dumps(report, indent=2, sort_keys=True))
    except OSError as e:
        logger.error(f"Failed to write report: {e}")
        return EXIT_CLI_ERROR
    return exit_code


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
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    p.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging (DEBUG level)",
    )
    p.add_argument(
        "--log-format",
        choices=["text", "json"],
        default="text",
        help="Log output format: text (default) or json (structured)",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    gen = sub.add_parser(
        "generate", help="Generate a provenance manifest for the given include globs."
    )
    gen.add_argument(
        "--root",
        default="",
        help=(
            "Root directory for manifest (default: current dir; with --from-hf the "
            "empty download directory; with --from-mlflow the logged model)"
        ),
    )
    gen.add_argument("--out", required=True, help="Output manifest JSON file path")
    gen.add_argument(
        "--include",
        action="append",
        default=[],
        help=(
            "Glob pattern for files to include (repeatable; required unless "
            "--from-hf or --from-mlflow, which default to **/*)"
        ),
    )
    gen.add_argument(
        "--meta", action="append", default=[], help="Metadata in key=value format"
    )
    gen.add_argument(
        "--format",
        choices=["json", "cyclonedx"],
        default="json",
        help="Output format: json (native manifest, default) or cyclonedx (CycloneDX 1.6 ML-BOM)",
    )
    mlbom = gen.add_argument_group(
        "ML-BOM options (--format cyclonedx)",
        "Added to what is derived from config.json, the README.md model card "
        "and requirements.txt in the root.",
    )
    mlbom.add_argument("--name", default="", help="Model name (default: root dir name)")
    mlbom.add_argument("--model-version", default="", help="Model version")
    mlbom.add_argument("--license", default="", help="Model license (SPDX id or name)")
    mlbom.add_argument(
        "--base-model",
        action="append",
        default=[],
        help="Base model this one derives from, e.g. openai-community/gpt2 (repeatable)",
    )
    mlbom.add_argument(
        "--dataset",
        action="append",
        default=[],
        help=(
            "Dataset as [name=]path-or-url; local files and directories are "
            "hashed (repeatable)"
        ),
    )
    mlbom.add_argument(
        "--requirements",
        action="append",
        default=[],
        help="requirements.txt listing framework/library packages (repeatable)",
    )
    gen.add_argument(
        "--report",
        default="",
        help="Also write a report envelope (in-toto Statement, kind aibom.generate)",
    )
    importer = gen.add_argument_group("importers")
    importer.add_argument(
        "--from-hf",
        default="",
        metavar="REPO_ID",
        help="Download a Hugging Face Hub model repo into --root first (hf extra)",
    )
    importer.add_argument(
        "--hf-revision",
        default="",
        help="Branch, tag or commit for --from-hf (default: main); pinned to a commit",
    )
    importer.add_argument(
        "--hf-allow",
        action="append",
        default=[],
        help="Only download files matching this pattern (repeatable), e.g. '*.json'",
    )
    importer.add_argument(
        "--from-mlflow",
        default="",
        metavar="RUN_DIR",
        help="MLflow file-store run directory (mlruns/<exp>/<run>) to describe",
    )
    importer.add_argument(
        "--mlflow-model",
        default="",
        help=(
            "Logged model to describe: its directory name under artifacts/ "
            "(MLflow 2) or its model id (MLflow 3). Default: the first one"
        ),
    )
    gen.add_argument(
        "--no-pickle-scan",
        action="store_true",
        help="Skip the static scan of pickle-based files (.pkl, .pt, .bin, ...)",
    )
    gen.add_argument(
        "--fail-on-pickle",
        choices=["dangerous", "unknown"],
        default="",
        help=(
            "Exit 4 when a pickle imports a dangerous global (dangerous), or "
            "anything not on the safe allowlist (unknown). Outputs are still written."
        ),
    )
    gen.set_defaults(func=_cmd_generate)

    keygen = sub.add_parser(
        "keygen", help="Generate an Ed25519 keypair for signing manifests."
    )
    keygen.add_argument(
        "--private-key", required=True, help="Output private key file path"
    )
    keygen.add_argument(
        "--public-key", required=True, help="Output public key file path"
    )
    keygen.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing key files (default: refuse)",
    )
    keygen.add_argument(
        "--algorithm",
        choices=["ed25519", "ecdsa-p256"],
        default="ed25519",
        help=(
            "ed25519 (default; sign, sign-file) or ecdsa-p256 "
            "(OMS model signing with sign-model)"
        ),
    )
    keygen.set_defaults(func=_cmd_keygen)

    sign = sub.add_parser(
        "sign", help="Sign a manifest and emit a detached signature JSON."
    )
    sign.add_argument("--manifest", required=True, help="Manifest JSON file path")
    sign.add_argument("--private-key", required=True, help="Private key PEM file path")
    sign.add_argument(
        "--out", default="", help="Output signature file path (default: stdout)"
    )
    sign.set_defaults(func=_cmd_sign)

    ver = sub.add_parser("verify", help="Verify a manifest against current files.")
    ver.add_argument("--manifest", required=True, help="Manifest JSON file path")
    ver.add_argument(
        "--root",
        default="",
        help=(
            "Directory holding the files to verify "
            "(default: the manifest's root, relative to the manifest file)"
        ),
    )
    ver.add_argument(
        "--out",
        default="",
        help="Write the report envelope to this file instead of stdout",
    )
    ver.add_argument(
        "--report",
        default="",
        help="Also write the report envelope (kind aibom.verify) to this file",
    )
    ver.add_argument(
        "--signature", default="", help="Signature JSON file path (optional)"
    )
    ver.add_argument(
        "--public-key",
        default="",
        help="Public key PEM file path (required with --signature)",
    )
    ver.add_argument(
        "--allow-extra",
        action="store_true",
        help=(
            "Report files inside the manifest's include scope that the manifest "
            "does not list, without failing (default: fail)"
        ),
    )
    ver.add_argument(
        "--format",
        choices=["json", "table", "legacy-json"],
        default="json",
        help=(
            "Output format: json (report envelope, default), table (human-readable) "
            "or legacy-json (the pre-1.0 report shape; deprecated)"
        ),
    )
    ver.set_defaults(func=_cmd_verify)

    sf = sub.add_parser(
        "sign-file",
        help="Sign any file (a report, a manifest, a BOM) with a DSSE in-toto envelope.",
    )
    sf.add_argument("file", help="File to sign")
    sf.add_argument("--key", default="", help="Ed25519 private key PEM (key mode)")
    sf.add_argument(
        "--sigstore",
        action="store_true",
        help="Sign keylessly with Sigstore (needs the 'sigstore' extra)",
    )
    sf.add_argument(
        "--identity-token",
        default="",
        help=(
            "OIDC identity token for --sigstore (default: $SIGSTORE_ID_TOKEN, "
            "ambient CI credentials, then an interactive browser flow)"
        ),
    )
    sf.add_argument(
        "--staging", action="store_true", help="Use Sigstore staging (testing only)"
    )
    sf.add_argument(
        "--out",
        default="",
        help="Signature path (default: <file>.sig.json, or <file>.sigstore.json)",
    )
    sf.set_defaults(func=_cmd_sign_file)

    vf = sub.add_parser(
        "verify-file", help="Verify a file against a sign-file signature."
    )
    vf.add_argument("file", help="File to verify")
    vf.add_argument(
        "--signature",
        default="",
        help="Signature path (default: <file>.sig.json, or <file>.sigstore.json)",
    )
    vf.add_argument(
        "--public-key", default="", help="Ed25519 public key PEM (key mode)"
    )
    vf.add_argument(
        "--identity",
        default="",
        help="Sigstore: expected signer identity (email or workflow URI)",
    )
    vf.add_argument(
        "--issuer",
        default="",
        help=(
            "Sigstore: expected OIDC issuer URL, "
            "e.g. https://token.actions.githubusercontent.com"
        ),
    )
    vf.add_argument(
        "--staging", action="store_true", help="Use Sigstore staging (testing only)"
    )
    vf.add_argument(
        "--report", default="", help="Also write the report envelope to this file"
    )
    vf.add_argument(
        "--format",
        choices=["json", "table"],
        default="json",
        help="Output: json (report envelope, default) or table",
    )
    vf.set_defaults(func=_cmd_verify_file)

    sp = sub.add_parser(
        "scan-pickle",
        help="Scan pickle-based model files for dangerous imports (never unpickles).",
    )
    sp.add_argument("paths", nargs="+", help="Files or directories to scan")
    sp.add_argument(
        "--strict",
        action="store_true",
        help="Also fail on imports not on the safe allowlist and on unparseable pickles",
    )
    sp.add_argument(
        "--report", default="", help="Also write the report envelope to this file"
    )
    sp.add_argument(
        "--format",
        choices=["json", "table"],
        default="json",
        help="Output: json (report envelope, default) or table",
    )
    sp.set_defaults(func=_cmd_scan_pickle)

    sm = sub.add_parser(
        "sign-model",
        help="Sign a model directory in OpenSSF Model Signing (OMS) format (oms extra).",
    )
    sm.add_argument("model_dir", help="Model directory to sign")
    sm.add_argument(
        "--key",
        default="",
        help="ECDSA private key PEM (keygen --algorithm ecdsa-p256)",
    )
    sm.add_argument(
        "--sigstore", action="store_true", help="Sign keylessly with Sigstore"
    )
    sm.add_argument(
        "--identity-token",
        default="",
        help="OIDC identity token for --sigstore (default: ambient CI credentials)",
    )
    sm.add_argument(
        "--staging", action="store_true", help="Use Sigstore staging (testing only)"
    )
    sm.add_argument(
        "--out", default="", help="Signature path (default: <model_dir>.oms.sig)"
    )
    sm.set_defaults(func=_cmd_sign_model)

    vm = sub.add_parser(
        "verify-model",
        help="Verify an OMS signature over a model directory (oms extra).",
    )
    vm.add_argument("model_dir", help="Model directory to verify")
    vm.add_argument(
        "--signature", default="", help="Signature path (default: <model_dir>.oms.sig)"
    )
    vm.add_argument("--public-key", default="", help="ECDSA public key PEM (key mode)")
    vm.add_argument("--identity", default="", help="Sigstore: expected signer identity")
    vm.add_argument("--issuer", default="", help="Sigstore: expected OIDC issuer URL")
    vm.add_argument(
        "--staging", action="store_true", help="Use Sigstore staging (testing only)"
    )
    vm.add_argument(
        "--report", default="", help="Also write the report envelope to this file"
    )
    vm.add_argument(
        "--format",
        choices=["json", "table"],
        default="json",
        help="Output: json (report envelope, default) or table",
    )
    vm.set_defaults(func=_cmd_verify_model)

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

    log_level = logging.DEBUG if args.verbose else logging.WARNING
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(log_level)

    log_format = getattr(args, "log_format", "text")
    if log_format == "json":
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s | %(levelname)-8s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )

    logging.basicConfig(level=log_level, handlers=[handler])

    configure_audit_log()

    cmd_name = args.cmd or "unknown"
    sanitized_args = {
        k: str(v)
        for k, v in vars(args).items()
        if k not in ("func", "cmd")
        and "key" not in k.lower()
        and "token" not in k.lower()
    }
    start_time = time.monotonic()

    try:
        exit_code = int(args.func(args))
        elapsed = (time.monotonic() - start_time) * 1000
        emit_audit_record(
            command=cmd_name,
            args=sanitized_args,
            outcome="success" if exit_code == 0 else "failure",
            exit_code=exit_code,
            duration_ms=elapsed,
        )
        return exit_code
    except (ValueError, FileNotFoundError, PermissionError) as e:
        logger.error(f"{type(e).__name__}: {e}")
        elapsed = (time.monotonic() - start_time) * 1000
        emit_audit_record(
            command=cmd_name,
            args=sanitized_args,
            outcome=f"error:{type(e).__name__}",
            exit_code=EXIT_CLI_ERROR,
            duration_ms=elapsed,
        )
        return EXIT_CLI_ERROR
    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        elapsed = (time.monotonic() - start_time) * 1000
        emit_audit_record(
            command=cmd_name,
            args=sanitized_args,
            outcome="interrupted",
            exit_code=EXIT_UNEXPECTED_ERROR,
            duration_ms=elapsed,
        )
        return EXIT_UNEXPECTED_ERROR
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        elapsed = (time.monotonic() - start_time) * 1000
        emit_audit_record(
            command=cmd_name,
            args=sanitized_args,
            outcome=f"unexpected:{type(e).__name__}",
            exit_code=EXIT_UNEXPECTED_ERROR,
            duration_ms=elapsed,
        )
        print(
            "\nAn unexpected error occurred. Please report this issue.",
            file=sys.stderr,
        )
        return EXIT_UNEXPECTED_ERROR
