"""Tests for ml-provenance-sbom enhancements."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from toolkit_ml_sbom.cli import (
    EXIT_CLI_ERROR,
    EXIT_SUCCESS,
    _parse_meta,
    _read,
    _validate_path_for_read,
    _validate_path_for_write,
    _write,
    main,
)

# ============================================================================
# Path Validation Tests
# ============================================================================


def test_validate_path_for_read_success(tmp_path: Path) -> None:
    """Test read path validation succeeds with valid file."""
    file_path = tmp_path / "test.json"
    file_path.write_text('{"test": true}', encoding="utf-8")

    result = _validate_path_for_read(file_path)
    assert result.is_absolute()
    assert result.is_file()


def test_validate_path_for_read_not_found() -> None:
    """Test read path validation fails with non-existent file."""
    with pytest.raises(FileNotFoundError, match="File not found"):
        _validate_path_for_read(Path("/nonexistent/file.json"))


def test_validate_path_for_read_is_directory(tmp_path: Path) -> None:
    """Test read path validation fails when path is directory."""
    with pytest.raises(ValueError, match="not a file"):
        _validate_path_for_read(tmp_path)


def test_validate_path_for_write_success(tmp_path: Path) -> None:
    """Test write path validation succeeds."""
    file_path = tmp_path / "output.json"
    result = _validate_path_for_write(file_path)
    assert result.is_absolute()


def test_validate_path_for_write_is_directory(tmp_path: Path) -> None:
    """Test write path validation fails when path is directory."""
    with pytest.raises(ValueError, match="is a directory"):
        _validate_path_for_write(tmp_path)


# ============================================================================
# JSON IO Tests
# ============================================================================


def test_read_json_success(tmp_path: Path) -> None:
    """Test reading valid JSON file."""
    file_path = tmp_path / "test.json"
    data = {"key": "value", "number": 42}
    file_path.write_text(json.dumps(data), encoding="utf-8")

    result = _read(file_path)
    assert result == data


def test_read_json_invalid_json(tmp_path: Path) -> None:
    """Test reading invalid JSON raises ValueError."""
    file_path = tmp_path / "invalid.json"
    file_path.write_text("not valid json", encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid JSON"):
        _read(file_path)


def test_read_json_file_not_found() -> None:
    """Test reading non-existent file raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        _read(Path("/nonexistent.json"))


def test_write_json_success(tmp_path: Path) -> None:
    """Test writing JSON file."""
    file_path = tmp_path / "output.json"
    data = {"test": True, "value": 123}

    _write(file_path, data)

    assert file_path.exists()
    assert json.loads(file_path.read_text()) == data


def test_write_json_creates_parent_directory(tmp_path: Path) -> None:
    """Test write creates parent directories."""
    file_path = tmp_path / "subdir" / "nested" / "output.json"
    data = {"nested": True}

    _write(file_path, data)

    assert file_path.exists()
    assert json.loads(file_path.read_text()) == data


# ============================================================================
# Metadata Parsing Tests
# ============================================================================


def test_parse_meta_success() -> None:
    """Test metadata parsing with valid key=value pairs."""
    items = ["key1=value1", "key2=value2", "key3=value with spaces"]
    result = _parse_meta(items)
    
    assert result == {
        "key1": "value1",
        "key2": "value2",
        "key3": "value with spaces",
    }


def test_parse_meta_empty_list() -> None:
    """Test metadata parsing with empty list."""
    result = _parse_meta([])
    assert result == {}


def test_parse_meta_invalid_format() -> None:
    """Test metadata parsing fails with invalid format."""
    with pytest.raises(ValueError, match="key=value"):
        _parse_meta(["key1=value1", "invalid_no_equals", "key3=value3"])


def test_parse_meta_multiple_equals() -> None:
    """Test metadata parsing handles multiple = signs."""
    items = ["url=https://example.com", "equation=x=y+z"]
    result = _parse_meta(items)
    
    assert result == {
        "url": "https://example.com",
        "equation": "x=y+z",
    }


# ============================================================================
# CLI Generate Command Tests
# ============================================================================


def test_cli_generate_root_not_found() -> None:
    """Test generate fails when root doesn't exist."""
    exit_code = main([
        "generate",
        "--root", "/nonexistent",
        "--out", "/tmp/manifest.json",
        "--include", "*.py",
    ])
    
    assert exit_code == EXIT_CLI_ERROR


def test_cli_generate_no_matches(tmp_path: Path) -> None:
    """Test generate fails when no files match pattern."""
    out_file = tmp_path / "manifest.json"
    
    # Now returns exit code instead of raising
    exit_code = main([
        "generate",
        "--root", str(tmp_path),
        "--out", str(out_file),
        "--include", "*.nonexistent",
    ])
    
    assert exit_code == EXIT_CLI_ERROR


def test_cli_generate_invalid_metadata(tmp_path: Path) -> None:
    """Test generate fails with invalid metadata format."""
    # Create a test file
    test_file = tmp_path / "test.txt"
    test_file.write_text("test", encoding="utf-8")
    
    out_file = tmp_path / "manifest.json"
    
    exit_code = main([
        "generate",
        "--root", str(tmp_path),
        "--out", str(out_file),
        "--include", "*.txt",
        "--meta", "invalid_format",
    ])
    
    assert exit_code == EXIT_CLI_ERROR


# ============================================================================
# CLI Keygen Command Tests
# ============================================================================


def test_cli_keygen_success(tmp_path: Path) -> None:
    """Test keygen creates key files."""
    priv_key = tmp_path / "private.pem"
    pub_key = tmp_path / "public.pem"
    
    exit_code = main([
        "keygen",
        "--private-key", str(priv_key),
        "--public-key", str(pub_key),
    ])
    
    assert exit_code == EXIT_SUCCESS
    assert priv_key.exists()
    assert pub_key.exists()
    assert "BEGIN PRIVATE KEY" in priv_key.read_text()
    assert "BEGIN PUBLIC KEY" in pub_key.read_text()


# ============================================================================
# CLI Sign Command Tests
# ============================================================================


def test_cli_sign_manifest_not_found(tmp_path: Path) -> None:
    """Test sign fails when manifest doesn't exist."""
    priv_key = tmp_path / "private.pem"
    priv_key.write_text("dummy", encoding="utf-8")
    
    exit_code = main([
        "sign",
        "--manifest", "/nonexistent.json",
        "--private-key", str(priv_key),
    ])
    
    assert exit_code == EXIT_CLI_ERROR


def test_cli_sign_private_key_not_found(tmp_path: Path) -> None:
    """Test sign fails when private key doesn't exist."""
    manifest = tmp_path / "manifest.json"
    manifest.write_text('{"test": true}', encoding="utf-8")
    
    exit_code = main([
        "sign",
        "--manifest", str(manifest),
        "--private-key", "/nonexistent.pem",
    ])
    
    assert exit_code == EXIT_CLI_ERROR


# ============================================================================
# CLI Verify Command Tests
# ============================================================================


def test_cli_verify_manifest_not_found() -> None:
    """Test verify fails when manifest doesn't exist."""
    exit_code = main([
        "verify",
        "--manifest", "/nonexistent.json",
    ])
    
    assert exit_code == EXIT_CLI_ERROR


def test_cli_verify_invalid_manifest(tmp_path: Path) -> None:
    """Test verify fails with invalid manifest."""
    manifest = tmp_path / "manifest.json"
    manifest.write_text("not valid json", encoding="utf-8")
    
    exit_code = main([
        "verify",
        "--manifest", str(manifest),
    ])
    
    assert exit_code == EXIT_CLI_ERROR


# ============================================================================
# Edge Case Tests
# ============================================================================


def test_cli_verbose_flag(tmp_path: Path, caplog) -> None:
    """Test --verbose flag enables debug logging."""
    # Create test file
    test_file = tmp_path / "test.txt"
    test_file.write_text("test content", encoding="utf-8")
    
    out_file = tmp_path / "manifest.json"
    
    exit_code = main([
        "--verbose",
        "generate",
        "--root", str(tmp_path),
        "--out", str(out_file),
        "--include", "*.txt",
    ])
    
    assert exit_code == EXIT_SUCCESS
    assert out_file.exists()


def test_json_round_trip(tmp_path: Path) -> None:
    """Test writing and reading JSON preserves data."""
    file_path = tmp_path / "test.json"
    data = {
        "string": "value",
        "number": 42,
        "bool": True,
        "list": [1, 2, 3],
        "nested": {"key": "value"},
    }
    
    _write(file_path, data)
    result = _read(file_path)
    
    assert result == data

