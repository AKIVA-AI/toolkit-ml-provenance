"""keygen must never silently destroy an existing signing identity."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from toolkit_ml_sbom.cli import EXIT_CLI_ERROR, EXIT_SUCCESS, main

pytest.importorskip("cryptography")


def _keygen(priv: Path, pub: Path, *extra: str) -> int:
    return main(
        ["keygen", "--private-key", str(priv), "--public-key", str(pub), *extra]
    )


def test_keygen_refuses_to_overwrite_private_key(tmp_path: Path) -> None:
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"
    priv.write_text("EXISTING PRIVATE KEY", encoding="utf-8")

    assert _keygen(priv, pub) == EXIT_CLI_ERROR
    assert priv.read_text(encoding="utf-8") == "EXISTING PRIVATE KEY"
    assert not pub.exists()


def test_keygen_refuses_to_overwrite_public_key(tmp_path: Path) -> None:
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"
    pub.write_text("EXISTING PUBLIC KEY", encoding="utf-8")

    assert _keygen(priv, pub) == EXIT_CLI_ERROR
    assert pub.read_text(encoding="utf-8") == "EXISTING PUBLIC KEY"
    assert not priv.exists()


def test_keygen_force_overwrites(tmp_path: Path) -> None:
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"
    priv.write_text("OLD", encoding="utf-8")
    pub.write_text("OLD", encoding="utf-8")

    assert _keygen(priv, pub, "--force") == EXIT_SUCCESS
    assert "PRIVATE KEY" in priv.read_text(encoding="utf-8")
    assert "PUBLIC KEY" in pub.read_text(encoding="utf-8")


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_private_key_is_created_owner_only(tmp_path: Path) -> None:
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"
    assert _keygen(priv, pub) == EXIT_SUCCESS
    assert stat.S_IMODE(priv.stat().st_mode) == 0o600
