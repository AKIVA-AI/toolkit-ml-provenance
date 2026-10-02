"""Signature verification must fail closed.

A signature check that is silently skipped must never be reported as passing.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from toolkit_ml_sbom.cli import (
    EXIT_CLI_ERROR,
    EXIT_SUCCESS,
    EXIT_VERIFICATION_FAILED,
    _format_table,
    main,
)


def _make_manifest(tmp_path: Path) -> Path:
    root = tmp_path / "model"
    root.mkdir()
    (root / "a.bin").write_bytes(b"weights")
    manifest = tmp_path / "manifest.json"
    rc = main(
        ["generate", "--root", str(root), "--out", str(manifest), "--include", "*.bin"]
    )
    assert rc == EXIT_SUCCESS
    return manifest


def test_signature_without_public_key_is_an_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A garbage signature with no --public-key must not pass."""
    manifest = _make_manifest(tmp_path)
    sig = tmp_path / "fake.sig"
    sig.write_text(json.dumps({"algorithm": "ed25519", "signature_b64": "AAAA"}))

    rc = main(["verify", "--manifest", str(manifest), "--signature", str(sig)])

    assert rc == EXIT_CLI_ERROR
    out = capsys.readouterr().out
    assert '"signature_ok": true' not in out


def test_public_key_without_signature_is_an_error(tmp_path: Path) -> None:
    """--public-key alone means the caller expected a signature check."""
    manifest = _make_manifest(tmp_path)
    pub = tmp_path / "pub.pem"
    pub.write_text("not-a-key", encoding="utf-8")

    rc = main(["verify", "--manifest", str(manifest), "--public-key", str(pub)])

    assert rc == EXIT_CLI_ERROR


def test_no_signature_reports_signature_not_checked(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Without a signature the report says null, never true."""
    manifest = _make_manifest(tmp_path)

    rc = main(["verify", "--manifest", str(manifest)])

    assert rc == EXIT_SUCCESS
    report = json.loads(capsys.readouterr().out)["predicate"]["details"]
    assert report["ok"] is True
    assert report["signature_ok"] is None


def test_table_shows_signature_not_checked() -> None:
    table = _format_table({"ok": True, "failures": [], "signature_ok": None})
    assert "Signature: NOT CHECKED" in table


def test_signature_covers_every_manifest_field(tmp_path: Path) -> None:
    """Editing any signed field (here: meta) after signing must fail verification."""
    pytest.importorskip("cryptography")
    manifest = _make_manifest(tmp_path)
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"
    sig = tmp_path / "m.sig.json"
    assert main(["keygen", "--private-key", str(priv), "--public-key", str(pub)]) == 0
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

    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["extra_field"] = "tampered"
    manifest.write_text(json.dumps(data), encoding="utf-8")

    rc = main(
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
    assert rc == EXIT_VERIFICATION_FAILED
