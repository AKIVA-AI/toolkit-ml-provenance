"""Each file appears in a manifest exactly once."""

from __future__ import annotations

import json
from pathlib import Path

from toolkit_ml_sbom import build_manifest
from toolkit_ml_sbom.cli import EXIT_SUCCESS, main


def _model(root: Path) -> None:
    (root / "weights" / "nested").mkdir(parents=True)
    (root / "weights" / "a.bin").write_bytes(b"a")
    (root / "weights" / "nested" / "b.bin").write_bytes(b"b")
    (root / "cfg.json").write_text("{}", encoding="utf-8")


def test_double_star_include_has_no_duplicate_entries(tmp_path: Path) -> None:
    """The README's `--include "**/*"` matches dirs and files; list each file once."""
    root = tmp_path / "model"
    _model(root)
    out = tmp_path / "manifest.json"

    rc = main(["generate", "--root", str(root), "--out", str(out), "--include", "**/*"])

    assert rc == EXIT_SUCCESS
    paths = [e["path"] for e in json.loads(out.read_text(encoding="utf-8"))["entries"]]
    assert paths == ["cfg.json", "weights/a.bin", "weights/nested/b.bin"]


def test_overlapping_includes_have_no_duplicate_entries(tmp_path: Path) -> None:
    root = tmp_path / "model"
    _model(root)
    out = tmp_path / "manifest.json"

    rc = main(
        [
            "generate",
            "--root",
            str(root),
            "--out",
            str(out),
            "--include",
            "weights/*.bin",
            "--include",
            "weights",
            "--include",
            "weights/**/*",
        ]
    )

    assert rc == EXIT_SUCCESS
    paths = [e["path"] for e in json.loads(out.read_text(encoding="utf-8"))["entries"]]
    assert paths == ["weights/a.bin", "weights/nested/b.bin"]


def test_build_manifest_dedupes_file_and_parent_dir(tmp_path: Path) -> None:
    _model(tmp_path)
    m = build_manifest(
        root=tmp_path,
        paths=[tmp_path / "weights", tmp_path / "weights" / "a.bin"],
        meta={},
    )
    assert [e["path"] for e in m.entries] == ["weights/a.bin", "weights/nested/b.bin"]
