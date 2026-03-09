"""Tests for hardening sprint: version flag, public API, CycloneDX, logging, format, edge cases."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from toolkit_ml_sbom import (
    Manifest,
    __version__,
    build_manifest,
    canonical_json_bytes,
    sha256_file,
)
from toolkit_ml_sbom.cli import (
    EXIT_SUCCESS,
    EXIT_VERIFICATION_FAILED,
    _format_table,
    build_parser,
    main,
)
from toolkit_ml_sbom.cyclonedx import cyclonedx_to_json_string, manifest_to_cyclonedx
from toolkit_ml_sbom.logging_config import JSONFormatter

# ============================================================================
# --version flag
# ============================================================================


def test_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    """--version prints version and exits."""
    with pytest.raises(SystemExit, match="0"):
        main(["--version"])
    captured = capsys.readouterr()
    assert __version__ in captured.out


def test_version_value() -> None:
    """Version string is a valid semver-like value."""
    parts = __version__.split(".")
    assert len(parts) == 3
    assert all(p.isdigit() for p in parts)


# ============================================================================
# Public API exports
# ============================================================================


def test_public_api_imports() -> None:
    """All declared public symbols are importable."""
    import toolkit_ml_sbom

    for name in toolkit_ml_sbom.__all__:
        assert hasattr(toolkit_ml_sbom, name), f"Missing export: {name}"


def test_manifest_class_exported() -> None:
    """Manifest is directly importable from the package."""
    from toolkit_ml_sbom import Manifest as M

    assert M is Manifest


def test_build_manifest_exported(tmp_path: Path) -> None:
    """build_manifest works when imported from package root."""
    f = tmp_path / "a.txt"
    f.write_text("hello", encoding="utf-8")
    m = build_manifest(root=tmp_path, paths=[f], meta={})
    assert len(m.entries) == 1


# ============================================================================
# CycloneDX format
# ============================================================================


def test_cyclonedx_basic_structure(tmp_path: Path) -> None:
    """CycloneDX output has required top-level fields."""
    f = tmp_path / "data.bin"
    f.write_bytes(b"\x00\x01\x02")
    m = build_manifest(root=tmp_path, paths=[f], meta={"model": "test"})
    cdx = manifest_to_cyclonedx(m)

    assert cdx["bomFormat"] == "CycloneDX"
    assert cdx["specVersion"] == "1.5"
    assert cdx["serialNumber"].startswith("urn:uuid:")
    assert cdx["version"] == 1
    assert "metadata" in cdx
    assert "components" in cdx


def test_cyclonedx_components_match_entries(tmp_path: Path) -> None:
    """Each manifest entry becomes a CycloneDX component."""
    for name in ["a.txt", "b.txt", "c.txt"]:
        (tmp_path / name).write_text(name, encoding="utf-8")
    m = build_manifest(
        root=tmp_path,
        paths=[tmp_path / "a.txt", tmp_path / "b.txt", tmp_path / "c.txt"],
        meta={},
    )
    cdx = manifest_to_cyclonedx(m)
    assert len(cdx["components"]) == 3

    for comp in cdx["components"]:
        assert comp["type"] == "data"
        assert len(comp["hashes"]) == 1
        assert comp["hashes"][0]["alg"] == "SHA-256"


def test_cyclonedx_metadata_includes_git_commit(tmp_path: Path) -> None:
    """Git commit appears in CycloneDX metadata properties."""
    f = tmp_path / "x.txt"
    f.write_text("x", encoding="utf-8")
    m = build_manifest(root=tmp_path, paths=[f], meta={})
    # Manually set git_commit for testing
    m2 = Manifest(
        version=m.version,
        created_ts=m.created_ts,
        root=m.root,
        git_commit="abc123deadbeef",
        entries=m.entries,
        meta=m.meta,
    )
    cdx = manifest_to_cyclonedx(m2)
    props = cdx["metadata"]["properties"]
    git_props = [p for p in props if p["name"] == "provenance:git-commit"]
    assert len(git_props) == 1
    assert git_props[0]["value"] == "abc123deadbeef"


def test_cyclonedx_custom_meta(tmp_path: Path) -> None:
    """Custom metadata appears in CycloneDX metadata properties."""
    f = tmp_path / "y.txt"
    f.write_text("y", encoding="utf-8")
    m = build_manifest(root=tmp_path, paths=[f], meta={"model": "gpt2", "version": "1"})
    cdx = manifest_to_cyclonedx(m)
    props = cdx["metadata"]["properties"]
    custom = {p["name"]: p["value"] for p in props if p["name"].startswith("custom:")}
    assert custom["custom:model"] == "gpt2"
    assert custom["custom:version"] == "1"


def test_cyclonedx_json_serializable(tmp_path: Path) -> None:
    """CycloneDX output is valid JSON."""
    f = tmp_path / "z.txt"
    f.write_text("z", encoding="utf-8")
    m = build_manifest(root=tmp_path, paths=[f], meta={})
    cdx = manifest_to_cyclonedx(m)
    s = cyclonedx_to_json_string(cdx)
    parsed = json.loads(s)
    assert parsed["bomFormat"] == "CycloneDX"


def test_cli_generate_cyclonedx(tmp_path: Path) -> None:
    """CLI generate --format cyclonedx produces CycloneDX output."""
    f = tmp_path / "model.bin"
    f.write_bytes(b"weights")
    out = tmp_path / "sbom.cdx.json"

    rc = main(
        [
            "generate",
            "--root",
            str(tmp_path),
            "--out",
            str(out),
            "--include",
            "*.bin",
            "--format",
            "cyclonedx",
        ]
    )
    assert rc == EXIT_SUCCESS
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["bomFormat"] == "CycloneDX"
    assert data["specVersion"] == "1.5"
    assert len(data["components"]) == 1


# ============================================================================
# Structured JSON logging
# ============================================================================


def test_json_formatter_basic() -> None:
    """JSONFormatter produces valid JSON."""
    fmt = JSONFormatter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg="hello %s",
        args=("world",),
        exc_info=None,
    )
    output = fmt.format(record)
    parsed = json.loads(output)
    assert parsed["level"] == "INFO"
    assert parsed["message"] == "hello world"
    assert "timestamp" in parsed
    assert parsed["logger"] == "test"


def test_json_formatter_with_exception() -> None:
    """JSONFormatter includes exception info."""
    fmt = JSONFormatter()
    try:
        raise ValueError("test error")
    except ValueError:
        import sys

        exc_info = sys.exc_info()

    record = logging.LogRecord(
        name="test",
        level=logging.ERROR,
        pathname="test.py",
        lineno=1,
        msg="failed",
        args=(),
        exc_info=exc_info,
    )
    output = fmt.format(record)
    parsed = json.loads(output)
    assert "exception" in parsed
    assert "ValueError" in parsed["exception"]


def test_cli_log_format_json(tmp_path: Path) -> None:
    """CLI --log-format json flag is accepted."""
    f = tmp_path / "f.txt"
    f.write_text("data", encoding="utf-8")
    out = tmp_path / "m.json"

    rc = main(
        [
            "--verbose",
            "--log-format",
            "json",
            "generate",
            "--root",
            str(tmp_path),
            "--out",
            str(out),
            "--include",
            "*.txt",
        ]
    )
    assert rc == EXIT_SUCCESS


# ============================================================================
# --format table for verify
# ============================================================================


def test_format_table_pass() -> None:
    """Table format for passing verification."""
    report = {"ok": True, "failures": [], "signature_ok": True}
    table = _format_table(report)
    assert "PASS" in table
    assert "All files verified" in table


def test_format_table_fail() -> None:
    """Table format for failed verification."""
    report = {
        "ok": False,
        "failures": [
            {"path": "weights/model.bin", "reason": "hash_mismatch"},
            {"path": "config.json", "reason": "missing"},
        ],
        "signature_ok": True,
    }
    table = _format_table(report)
    assert "FAIL" in table
    assert "weights/model.bin" in table
    assert "hash_mismatch" in table
    assert "missing" in table


def test_format_table_sig_failed() -> None:
    """Table format shows signature failure."""
    report = {
        "ok": False,
        "failures": [{"path": "", "reason": "signature_invalid"}],
        "signature_ok": False,
    }
    table = _format_table(report)
    assert "FAILED" in table


def test_cli_verify_table_format(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """CLI verify --format table produces table output."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "a.txt").write_text("hello", encoding="utf-8")
    manifest = tmp_path / "m.json"

    main(
        [
            "generate",
            "--root",
            str(root),
            "--out",
            str(manifest),
            "--include",
            "*.txt",
        ]
    )

    rc = main(
        [
            "verify",
            "--manifest",
            str(manifest),
            "--format",
            "table",
        ]
    )
    assert rc == EXIT_SUCCESS
    captured = capsys.readouterr()
    assert "PASS" in captured.out


# ============================================================================
# Edge case tests
# ============================================================================


def test_empty_manifest_from_json() -> None:
    """Manifest.from_json with empty entries list."""
    obj = {
        "version": 1,
        "created_ts": 0.0,
        "root": ".",
        "git_commit": "",
        "entries": [],
        "meta": {},
    }
    m = Manifest.from_json(obj)
    assert m.entries == []
    assert m.version == 1


def test_manifest_from_json_not_object() -> None:
    """Manifest.from_json rejects non-dict input."""
    with pytest.raises(ValueError, match="manifest_not_object"):
        Manifest.from_json("string")

    with pytest.raises(ValueError, match="manifest_not_object"):
        Manifest.from_json([1, 2, 3])


def test_manifest_from_json_entries_not_list() -> None:
    """Manifest.from_json rejects non-list entries."""
    with pytest.raises(ValueError, match="manifest_entries_not_list"):
        Manifest.from_json({"entries": "not a list"})


def test_manifest_from_json_meta_not_object() -> None:
    """Manifest.from_json rejects non-dict meta."""
    with pytest.raises(ValueError, match="manifest_meta_not_object"):
        Manifest.from_json({"entries": [], "meta": "not a dict"})


def test_manifest_from_json_missing_fields() -> None:
    """Manifest.from_json handles missing optional fields with defaults."""
    obj = {"entries": []}
    m = Manifest.from_json(obj)
    assert m.version == 0
    assert m.created_ts == 0.0
    assert m.root == "."
    assert m.git_commit == ""
    assert m.meta == {}


def test_manifest_round_trip() -> None:
    """Manifest serializes and deserializes correctly."""
    m = Manifest(
        version=1,
        created_ts=1234567890.0,
        root="/some/path",
        git_commit="abc123",
        entries=[{"path": "x.bin", "size": 10, "sha256": "deadbeef"}],
        meta={"key": "val"},
    )
    j = m.to_json()
    m2 = Manifest.from_json(j)
    assert m2.version == m.version
    assert m2.root == m.root
    assert m2.entries == m.entries
    assert m2.meta == m.meta


def test_verify_empty_manifest(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Verifying an empty manifest (no entries) should pass."""
    manifest_data = {
        "version": 1,
        "created_ts": 0.0,
        "root": str(tmp_path),
        "git_commit": "",
        "entries": [],
        "meta": {},
    }
    mf = tmp_path / "empty.json"
    mf.write_text(json.dumps(manifest_data), encoding="utf-8")

    rc = main(["verify", "--manifest", str(mf)])
    assert rc == EXIT_SUCCESS


def test_verify_missing_file(tmp_path: Path) -> None:
    """Verify detects missing files."""
    manifest_data = {
        "version": 1,
        "created_ts": 0.0,
        "root": str(tmp_path),
        "git_commit": "",
        "entries": [{"path": "nonexistent.bin", "size": 0, "sha256": "abc"}],
        "meta": {},
    }
    mf = tmp_path / "m.json"
    mf.write_text(json.dumps(manifest_data), encoding="utf-8")

    rc = main(["verify", "--manifest", str(mf)])
    assert rc == EXIT_VERIFICATION_FAILED


def test_verify_corrupt_file(tmp_path: Path) -> None:
    """Verify detects modified files (hash mismatch)."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "data.txt").write_text("original", encoding="utf-8")

    manifest = tmp_path / "m.json"
    main(
        [
            "generate",
            "--root",
            str(root),
            "--out",
            str(manifest),
            "--include",
            "*.txt",
        ]
    )

    # Corrupt the file
    (root / "data.txt").write_text("modified", encoding="utf-8")

    rc = main(["verify", "--manifest", str(manifest)])
    assert rc == EXIT_VERIFICATION_FAILED


def test_sha256_empty_file(tmp_path: Path) -> None:
    """SHA-256 of empty file is the known constant."""
    f = tmp_path / "empty"
    f.write_bytes(b"")
    h = sha256_file(f)
    # SHA-256 of empty string
    assert h == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_canonical_json_deterministic() -> None:
    """canonical_json_bytes is deterministic regardless of key order."""
    obj1 = {"b": 2, "a": 1}
    obj2 = {"a": 1, "b": 2}
    assert canonical_json_bytes(obj1) == canonical_json_bytes(obj2)


def test_invalid_signature_verify(tmp_path: Path) -> None:
    """Verify with a tampered signature file fails."""
    pytest.importorskip("cryptography")

    root = tmp_path / "repo"
    root.mkdir()
    (root / "a.txt").write_text("hello", encoding="utf-8")

    manifest = tmp_path / "m.json"
    main(["generate", "--root", str(root), "--out", str(manifest), "--include", "*.txt"])

    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"
    main(["keygen", "--private-key", str(priv), "--public-key", str(pub)])

    sig_file = tmp_path / "sig.json"
    main(["sign", "--manifest", str(manifest), "--private-key", str(priv), "--out", str(sig_file)])

    # Tamper with signature
    sig_data = json.loads(sig_file.read_text(encoding="utf-8"))
    sig_data["signature_b64"] = "AAAA" + sig_data["signature_b64"][4:]
    sig_file.write_text(json.dumps(sig_data), encoding="utf-8")

    rc = main(
        [
            "verify",
            "--manifest",
            str(manifest),
            "--signature",
            str(sig_file),
            "--public-key",
            str(pub),
        ]
    )
    assert rc == EXIT_VERIFICATION_FAILED


def test_build_parser_has_version() -> None:
    """Parser includes --version action."""
    parser = build_parser()
    # Check that --version is registered
    # Just try parsing --version
    with pytest.raises(SystemExit, match="0"):
        parser.parse_args(["--version"])
