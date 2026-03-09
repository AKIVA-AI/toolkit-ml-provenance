from __future__ import annotations

import subprocess  # nosec B404
import time
from dataclasses import dataclass
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

    def to_json(self) -> dict[str, Any]:
        return {
            "version": int(self.version),
            "created_ts": float(self.created_ts),
            "root": str(self.root),
            "git_commit": str(self.git_commit),
            "entries": list(self.entries),
            "meta": dict(self.meta),
        }

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
        return Manifest(
            version=int(obj.get("version", 0)),
            created_ts=float(obj.get("created_ts", 0.0)),
            root=str(obj.get("root") or "."),
            git_commit=str(obj.get("git_commit") or ""),
            entries=[dict(e) for e in entries],
            meta={str(k): str(v) for k, v in meta.items()},
        )


def build_manifest(*, root: Path, paths: list[Path], meta: dict[str, str]) -> Manifest:
    entries: list[dict[str, Any]] = []
    for p in sorted(set(paths)):
        p = p.resolve()
        if p.is_dir():
            for f in sorted(x for x in p.rglob("*") if x.is_file()):
                entries.append(_entry(root=root, path=f))
        else:
            entries.append(_entry(root=root, path=p))
    return Manifest(
        version=1,
        created_ts=_utc_ts(),
        root=str(root.resolve()),
        git_commit=_try_git_commit(root),
        entries=entries,
        meta=dict(meta),
    )


def _entry(*, root: Path, path: Path) -> dict[str, Any]:
    rel = str(path.resolve().relative_to(root.resolve())) if path.is_absolute() else str(path)
    return {
        "path": rel,
        "size": int(path.stat().st_size),
        "sha256": sha256_file(path),
    }
