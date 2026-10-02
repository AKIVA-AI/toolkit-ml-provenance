"""Toolkit report envelope v1: an in-toto Statement v1 whose predicate is a report.

See ``docs/report-envelope.md`` and ``schemas/report-envelope.v1.json``.
Envelopes are written as canonical JSON (UTF-8, sorted keys, no insignificant
whitespace, trailing newline) so their SHA-256 is stable and they can be signed
with ``toolkit-mlsbom sign-file``.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
TOOL_NAME = "toolkit-ml-provenance"
PREDICATE_TYPE = f"https://github.com/AKIVA-AI/{TOOL_NAME}/report/v1"
VERDICTS = ("pass", "fail", "error")


def canonical_dumps(obj: Any) -> bytes:
    """Serialize ``obj`` as canonical JSON bytes with a trailing newline."""
    text = json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return text.encode("utf-8") + b"\n"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def resource(name: str, sha256: str) -> dict[str, Any]:
    """An in-toto ResourceDescriptor with a SHA-256 digest."""
    return {"name": name, "digest": {"sha256": sha256}}


def file_resource(path: Path, name: str | None = None) -> dict[str, Any]:
    """A ResourceDescriptor for a file, hashed over its exact bytes."""
    from .hashing import sha256_file

    return resource(name or path.name, sha256_file(path))


def tree_digest(entries: Iterable[Mapping[str, Any]]) -> str:
    """Digest of a file set: SHA-256 over the canonical JSON of its sorted entries.

    Each entry contributes ``path``, ``sha256`` and ``size``, so two directories
    have the same digest exactly when they hold the same files with the same
    content.
    """
    rows = sorted(
        (
            {
                "path": str(e.get("path", "")),
                "sha256": str(e.get("sha256", "")),
                "size": int(e.get("size", 0)),
            }
            for e in entries
        ),
        key=lambda r: str(r["path"]),
    )
    return sha256_bytes(canonical_dumps(rows))


def utc_now() -> str:
    """Current time as RFC 3339 UTC with second precision, e.g. 2026-09-26T18:00:00Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_report(
    *,
    kind: str,
    verdict: str,
    exit_code: int,
    subject: list[dict[str, Any]],
    inputs: list[dict[str, Any]] | None = None,
    summary: dict[str, Any] | None = None,
    details: dict[str, Any] | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Build a report envelope, refusing inconsistent verdicts.

    ``pass`` requires exit code 0; ``fail`` and ``error`` require a non-zero code.
    """
    if verdict not in VERDICTS:
        raise ValueError(f"invalid verdict: {verdict!r}")
    if (verdict == "pass") != (exit_code == 0):
        raise ValueError(
            f"verdict {verdict!r} is inconsistent with exit code {exit_code}"
        )
    if not subject:
        raise ValueError("report needs at least one subject")
    return {
        "_type": STATEMENT_TYPE,
        "subject": list(subject),
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "tool": {"name": TOOL_NAME, "version": __version__},
            "kind": kind,
            "created_at": created_at or utc_now(),
            "verdict": verdict,
            "exit_code": int(exit_code),
            "inputs": list(inputs or []),
            "summary": dict(summary or {}),
            "details": dict(details or {}),
        },
    }


def write_report(path: Path, report: Mapping[str, Any]) -> None:
    """Write ``report`` to ``path`` as canonical JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_dumps(report))


def is_statement(obj: Any) -> bool:
    """True when ``obj`` looks like an in-toto Statement v1."""
    return (
        isinstance(obj, dict)
        and obj.get("_type") == STATEMENT_TYPE
        and isinstance(obj.get("subject"), list)
        and isinstance(obj.get("predicateType"), str)
    )
