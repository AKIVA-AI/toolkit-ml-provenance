"""Manifests must verify on another machine, path and OS.

Entries are stored relative to the manifest root with POSIX separators, and the
root is stored relative to the manifest file, never as an absolute path.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path, PurePosixPath, PureWindowsPath

from toolkit_ml_sbom import build_manifest
from toolkit_ml_sbom.cli import EXIT_SUCCESS, EXIT_VERIFICATION_FAILED, main
from toolkit_ml_sbom.hashing import sha256_file


def _model(root: Path) -> None:
    (root / "weights" / "shards").mkdir(parents=True)
    (root / "weights" / "shards" / "a.bin").write_bytes(b"shard-a")
    (root / "config.json").write_text('{"layers": 2}', encoding="utf-8")


def _generate(root: Path, out: Path, *includes: str) -> None:
    args = ["generate", "--root", str(root), "--out", str(out)]
    for inc in includes:
        args += ["--include", inc]
    assert main(args) == EXIT_SUCCESS


def _is_absolute_anywhere(p: str) -> bool:
    return PurePosixPath(p).is_absolute() or PureWindowsPath(p).is_absolute()


def test_manifest_root_is_relative_to_manifest_file(tmp_path: Path) -> None:
    root = tmp_path / "model"
    _model(root)
    out = tmp_path / "out" / "manifest.json"

    _generate(root, out, "config.json", "weights/**/*.bin")

    data = json.loads(out.read_text(encoding="utf-8"))
    assert not _is_absolute_anywhere(data["root"])
    assert data["root"] == "../model"


def test_entry_paths_use_posix_separators(tmp_path: Path) -> None:
    root = tmp_path / "model"
    _model(root)
    out = tmp_path / "manifest.json"

    _generate(root, out, "weights/**/*.bin")

    data = json.loads(out.read_text(encoding="utf-8"))
    paths = [e["path"] for e in data["entries"]]
    assert paths == ["weights/shards/a.bin"]
    assert all("\\" not in p for p in paths)


def test_library_build_manifest_is_portable(tmp_path: Path) -> None:
    _model(tmp_path)
    m = build_manifest(
        root=tmp_path, paths=[tmp_path / "weights"], meta={}, manifest_dir=tmp_path
    )
    assert m.root == "."
    assert [e["path"] for e in m.entries] == ["weights/shards/a.bin"]


def test_manifest_verifies_after_moving_the_whole_tree(tmp_path: Path) -> None:
    site = tmp_path / "build-machine"
    root = site / "model"
    _model(root)
    out = site / "manifest.json"
    _generate(root, out, "config.json", "weights/**/*.bin")

    moved = tmp_path / "deploy-machine" / "somewhere" / "else"
    shutil.copytree(site, moved)
    shutil.rmtree(site)

    assert main(["verify", "--manifest", str(moved / "manifest.json")]) == EXIT_SUCCESS


def test_hand_written_posix_manifest_verifies_on_any_os(tmp_path: Path) -> None:
    """A manifest produced on Linux (POSIX paths, relative root) verifies here."""
    root = tmp_path / "model"
    _model(root)
    shard = root / "weights" / "shards" / "a.bin"
    manifest = {
        "version": 1,
        "created_ts": 0.0,
        "root": "model",
        "git_commit": "",
        "entries": [
            {
                "path": "weights/shards/a.bin",
                "size": shard.stat().st_size,
                "sha256": sha256_file(shard),
            }
        ],
        "meta": {},
        "include": ["weights/**/*.bin"],
    }
    mf = tmp_path / "manifest.json"
    mf.write_text(json.dumps(manifest), encoding="utf-8")

    assert main(["verify", "--manifest", str(mf)]) == EXIT_SUCCESS


def test_verify_root_override(tmp_path: Path) -> None:
    """--root verifies a model that no longer sits beside its manifest."""
    root = tmp_path / "model"
    _model(root)
    out = tmp_path / "manifests" / "manifest.json"
    _generate(root, out, "config.json")

    relocated = tmp_path / "mnt" / "models" / "m1"
    shutil.copytree(root, relocated)
    shutil.rmtree(root)

    assert main(["verify", "--manifest", str(out)]) == EXIT_VERIFICATION_FAILED
    assert (
        main(["verify", "--manifest", str(out), "--root", str(relocated)])
        == EXIT_SUCCESS
    )
