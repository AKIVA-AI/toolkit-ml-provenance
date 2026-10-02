from __future__ import annotations

import os
import subprocess  # nosec B404
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .hashing import sha256_file


def _utc_ts() -> float:
    return time.time()


def _try_git_commit(root: Path) -> str:
    try:
        r = subprocess.run(  # nosec
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=2.0,
        )
        return r.stdout.strip()
    except Exception:
        return ""


@dataclass(frozen=True)
class Manifest:
    version: int
    created_ts: float
    root: str
    git_commit: str
    entries: list[dict[str, Any]]
    meta: dict[str, str]
    # Include globs that define the manifest's scope. None for older manifests
    # that did not record them; verify then treats the whole root as the scope.
    include: list[str] | None = field(default=None)

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "version": int(self.version),
            "created_ts": float(self.created_ts),
            "root": str(self.root),
            "git_commit": str(self.git_commit),
            "entries": list(self.entries),
            "meta": dict(self.meta),
        }
        if self.include is not None:
            out["include"] = list(self.include)
        return out

    @staticmethod
    def from_json(obj: Any) -> Manifest:
        if not isinstance(obj, dict):
            raise ValueError("manifest_not_object")
        entries = obj.get("entries")
        if not isinstance(entries, list):
            raise ValueError("manifest_entries_not_list")
        meta = obj.get("meta")
        if meta is None:
            meta = {}
        if not isinstance(meta, dict):
            raise ValueError("manifest_meta_not_object")
        include = obj.get("include")
        if include is not None and not (
            isinstance(include, list) and all(isinstance(i, str) for i in include)
        ):
            raise ValueError("manifest_include_not_string_list")
        return Manifest(
            version=int(obj.get("version", 0)),
            created_ts=float(obj.get("created_ts", 0.0)),
            root=str(obj.get("root") or "."),
            git_commit=str(obj.get("git_commit") or ""),
            entries=[dict(e) for e in entries],
            meta={str(k): str(v) for k, v in meta.items()},
            include=list(include) if include is not None else None,
        )


def relative_root(root: Path, manifest_dir: Path) -> str:
    """Return ``root`` relative to ``manifest_dir`` as a POSIX path.

    Falls back to the absolute POSIX path when no relative path exists
    (for example, different drives on Windows).
    """
    try:
        rel = os.path.relpath(root.resolve(), manifest_dir.resolve())
    except ValueError:
        return root.resolve().as_posix()
    return Path(rel).as_posix()


def expand_files(paths: list[Path]) -> list[Path]:
    """Resolve ``paths`` to a de-duplicated list of files.

    Directories are expanded recursively, so a directory and a file inside it
    (as produced by a ``**/*`` glob) yield that file once.
    """
    files: set[Path] = set()
    for p in paths:
        p = p.resolve()
        if p.is_dir():
            files.update(x.resolve() for x in p.rglob("*") if x.is_file())
        else:
            files.add(p)
    return sorted(files)


def scope_files(root: Path, include: list[str] | None) -> list[Path]:
    """Return the files under ``root`` that fall inside a manifest's scope.

    The scope is every file matched by the ``include`` globs (directories are
    expanded recursively). With no recorded globs the scope is the whole root.
    Matches outside ``root`` are ignored.
    """
    root = root.resolve()
    if include is None:
        matches = [root]
    else:
        matches = [m for pattern in include for m in root.glob(pattern)]
    return [f for f in expand_files(matches) if f.is_relative_to(root)]


def build_manifest(
    *,
    root: Path,
    paths: list[Path],
    meta: dict[str, str],
    manifest_dir: Path | None = None,
    include: list[str] | None = None,
) -> Manifest:
    """Hash ``paths`` (directories are expanded recursively) under ``root``.

    Entry paths are relative to ``root`` with POSIX separators. The stored root
    is relative to ``manifest_dir``, the directory the manifest will be written
    to; when omitted, the manifest is assumed to live in ``root`` (root ``"."``).
    ``include`` records the globs that produced ``paths`` so that ``verify``
    can detect files added inside that scope later.
    """
    root = root.resolve()
    entries = [_entry(root=root, path=f) for f in expand_files(paths)]
    entries.sort(key=lambda e: str(e["path"]))
    return Manifest(
        version=2 if include is not None else 1,
        created_ts=_utc_ts(),
        root=relative_root(root, manifest_dir if manifest_dir is not None else root),
        git_commit=_try_git_commit(root),
        entries=entries,
        meta=dict(meta),
        include=list(include) if include is not None else None,
    )


def _entry(*, root: Path, path: Path) -> dict[str, Any]:
    rel = path.resolve().relative_to(root).as_posix()
    return {
        "path": rel,
        "size": int(path.stat().st_size),
        "sha256": sha256_file(path),
    }
