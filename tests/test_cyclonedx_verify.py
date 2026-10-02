"""verify takes the native JSON manifest; a CycloneDX export gets a clear error."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from toolkit_ml_sbom.cli import EXIT_CLI_ERROR, EXIT_SUCCESS, main


def test_verify_rejects_cyclonedx_with_clear_message(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    root = tmp_path / "model"
    root.mkdir()
    (root / "w.bin").write_bytes(b"w")
    sbom = tmp_path / "sbom.cdx.json"
    rc = main(
        [
            "generate",
            "--root",
            str(root),
            "--out",
            str(sbom),
            "--include",
            "*.bin",
            "--format",
            "cyclonedx",
        ]
    )
    assert rc == EXIT_SUCCESS

    with caplog.at_level(logging.ERROR):
        rc = main(["verify", "--manifest", str(sbom)])

    assert rc == EXIT_CLI_ERROR
    assert "CycloneDX" in caplog.text
    assert "native JSON manifest" in caplog.text
