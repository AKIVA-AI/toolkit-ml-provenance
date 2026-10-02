"""Audit logging for CLI operations.

Emits structured JSON audit records to a configurable audit log file.
Each record captures: timestamp, command, user, arguments, outcome, and duration.
"""

from __future__ import annotations

import getpass
import json
import logging
import os
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_AUDIT_LOG_PATH: Path | None = None


def configure_audit_log(path: Path | None = None) -> None:
    """Configure the audit log output path.

    Args:
        path: Path to audit log file. If None, uses MLSBOM_AUDIT_LOG env var.
              If neither is set, audit logging is disabled.
    """
    global _AUDIT_LOG_PATH
    if path is not None:
        _AUDIT_LOG_PATH = path
    else:
        env_path = os.environ.get("MLSBOM_AUDIT_LOG")
        if env_path:
            _AUDIT_LOG_PATH = Path(env_path)
        else:
            _AUDIT_LOG_PATH = None


def emit_audit_record(
    *,
    command: str,
    args: dict[str, Any],
    outcome: str,
    exit_code: int,
    duration_ms: float,
) -> None:
    """Emit a single audit record to the audit log.

    Args:
        command: CLI subcommand name (generate, verify, sign, keygen).
        args: Sanitized command arguments (no secrets).
        outcome: Human-readable outcome description.
        exit_code: CLI exit code.
        duration_ms: Command execution duration in milliseconds.
    """
    if _AUDIT_LOG_PATH is None:
        return

    record = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tool": "toolkit-mlsbom",
        "command": command,
        "user": _safe_username(),
        "args": args,
        "outcome": outcome,
        "exit_code": exit_code,
        "duration_ms": round(duration_ms, 2),
    }

    try:
        _AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with _AUDIT_LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, separators=(",", ":")) + "\n")
    except OSError as e:
        logger.warning(f"Failed to write audit log: {e}")


def _safe_username() -> str:
    """Get current username safely."""
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"
