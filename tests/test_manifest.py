from __future__ import annotations

import json
from pathlib import Path

import pytest

from toolkit_ml_sbom.cli import main


def test_generate_and_verify(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "configs").mkdir()
    (root / "weights").mkdir()
    (root / "configs" / "c.json").write_text(json.dumps({"a": 1}), encoding="utf-8")
    (root / "weights" / "w.bin").write_bytes(b"abc")

    out = tmp_path / "m.json"
    assert (
        main(
            [
                "generate",
                "--root",
                str(root),
                "--out",
                str(out),
                "--include",
                "configs/*.json",
                "--include",
                "weights/*",
                "--meta",
                "model=test",
            ]
        )
        == 0
    )
    assert main(["verify", "--manifest", str(out)]) == 0

    (root / "weights" / "w.bin").write_bytes(b"def")
    assert main(["verify", "--manifest", str(out)]) == 4


def test_sign_and_verify_signature(tmp_path: Path) -> None:
    pytest.importorskip("cryptography")

    root = tmp_path / "repo"
    root.mkdir()
    (root / "a.txt").write_text("hello", encoding="utf-8")

    manifest = tmp_path / "m.json"
    assert (
        main(
            [
                "generate",
                "--root",
                str(root),
                "--out",
                str(manifest),
                "--include",
                "a.txt",
            ]
        )
        == 0
    )

    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"
    assert main(["keygen", "--private-key", str(priv), "--public-key", str(pub)]) == 0

    sig = tmp_path / "m.sig.json"
    assert (
        main(
            [
                "sign",
                "--manifest",
                str(manifest),
                "--private-key",
                str(priv),
                "--out",
                str(sig),
            ]
        )
        == 0
    )

    assert (
        main(
            [
                "verify",
                "--manifest",
                str(manifest),
                "--signature",
                str(sig),
                "--public-key",
                str(pub),
            ]
        )
        == 0
    )
