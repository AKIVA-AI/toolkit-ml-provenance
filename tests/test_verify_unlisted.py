"""Files added after the manifest was made must be reported.

An extra file in a model directory (a pickle payload, a swapped tokenizer, a
new adapter) is the canonical supply-chain attack. `verify` re-applies the
manifest's include globs and fails on any file the manifest does not list,
unless `--allow-extra` is given.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from toolkit_ml_sbom import Manifest
from toolkit_ml_sbom.cli import EXIT_SUCCESS, EXIT_VERIFICATION_FAILED, main
from toolkit_ml_sbom.hashing import sha256_file


def _model(root: Path) -> None:
    (root / "weights").mkdir(parents=True)
    (root / "weights" / "a.bin").write_bytes(b"a")
    (root / "cfg.json").write_text("{}", encoding="utf-8")


def _generate(root: Path, out: Path, *includes: str) -> None:
    args = ["generate", "--root", str(root), "--out", str(out)]
    for inc in includes:
        args += ["--include", inc]
    assert main(args) == EXIT_SUCCESS


def _verify(
    manifest: Path, capsys: pytest.CaptureFixture[str], *extra: str
) -> tuple[int, dict]:
    capsys.readouterr()
    rc = main(["verify", "--manifest", str(manifest), *extra])
    return rc, json.loads(capsys.readouterr().out)["predicate"]["details"]


def test_manifest_records_include_patterns(tmp_path: Path) -> None:
    root = tmp_path / "model"
    _model(root)
    out = tmp_path / "manifest.json"
    _generate(root, out, "weights/*", "cfg.json")

    m = Manifest.from_json(json.loads(out.read_text(encoding="utf-8")))
    assert m.include == ["weights/*", "cfg.json"]


def test_added_file_fails_verification(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "model"
    _model(root)
    out = tmp_path / "manifest.json"
    _generate(root, out, "weights/*", "cfg.json")

    (root / "weights" / "evil.bin").write_bytes(b"payload")

    rc, report = _verify(out, capsys)
    assert rc == EXIT_VERIFICATION_FAILED
    assert report["ok"] is False
    assert {"path": "weights/evil.bin", "reason": "unlisted"} in report["failures"]
    assert report["unlisted"] == ["weights/evil.bin"]


def test_added_file_in_new_subdirectory_fails_verification(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "model"
    _model(root)
    out = tmp_path / "manifest.json"
    _generate(root, out, "**/*")

    (root / "adapters").mkdir()
    (root / "adapters" / "lora.pkl").write_bytes(b"pickle")

    rc, report = _verify(out, capsys)
    assert rc == EXIT_VERIFICATION_FAILED
    assert report["unlisted"] == ["adapters/lora.pkl"]


def test_allow_extra_reports_but_does_not_fail(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "model"
    _model(root)
    out = tmp_path / "manifest.json"
    _generate(root, out, "weights/*")
    (root / "weights" / "evil.bin").write_bytes(b"payload")

    rc, report = _verify(out, capsys, "--allow-extra")
    assert rc == EXIT_SUCCESS
    assert report["ok"] is True
    assert report["unlisted"] == ["weights/evil.bin"]


def test_files_outside_include_scope_are_not_flagged(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "model"
    _model(root)
    out = tmp_path / "manifest.json"
    _generate(root, out, "weights/*")
    (root / "README.md").write_text("notes", encoding="utf-8")

    rc, report = _verify(out, capsys)
    assert rc == EXIT_SUCCESS
    assert report["unlisted"] == []


def test_manifest_inside_root_is_neither_listed_nor_unlisted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Generating twice with the manifest inside the scope stays verifiable."""
    root = tmp_path / "model"
    _model(root)
    out = root / "manifest.json"
    _generate(root, out, "**/*")
    _generate(root, out, "**/*")

    paths = [e["path"] for e in json.loads(out.read_text(encoding="utf-8"))["entries"]]
    assert "manifest.json" not in paths

    rc, report = _verify(out, capsys)
    assert rc == EXIT_SUCCESS
    assert report["unlisted"] == []


def test_legacy_manifest_without_include_checks_whole_root(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Manifests without recorded include globs fail closed: scope is the whole root."""
    root = tmp_path / "model"
    _model(root)
    a = root / "weights" / "a.bin"
    legacy = {
        "version": 1,
        "created_ts": 0.0,
        "root": str(root),
        "git_commit": "",
        "entries": [{"path": "weights/a.bin", "size": 1, "sha256": sha256_file(a)}],
        "meta": {},
    }
    mf = tmp_path / "legacy.json"
    mf.write_text(json.dumps(legacy), encoding="utf-8")

    rc, report = _verify(mf, capsys)
    assert rc == EXIT_VERIFICATION_FAILED
    assert report["unlisted"] == ["cfg.json"]
