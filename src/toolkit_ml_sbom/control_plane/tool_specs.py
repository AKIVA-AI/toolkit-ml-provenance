"""
CLI command -> ToolSpec mapping for toolkit-ml-provenance.

Maps the 4 CLI subcommands (generate, keygen, sign, verify) to ToolSpec
contracts with appropriate permission scope and approval policy.

'generate', 'verify' are READ_ONLY + AUTO (they read files and produce reports).
'keygen' is WORKSPACE_WRITE + REQUIRE_APPROVAL (writes key files to disk).
'sign' is WORKSPACE_WRITE + REQUIRE_APPROVAL (writes signature files to disk).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .contracts import ApprovalPolicy, AuthorityBoundary, PermissionScope, ToolSpec


@dataclass
class ToolkitCommandSpec:
    """Maps a CLI subcommand name to its ToolSpec and authority boundary."""

    command: str
    spec: ToolSpec
    boundary: AuthorityBoundary


def _make_spec(
    name: str,
    description: str,
    scope: PermissionScope = PermissionScope.READ_ONLY,
    input_schema: dict[str, Any] | None = None,
) -> ToolSpec:
    """Create a ToolSpec for an ml-provenance CLI command."""
    return ToolSpec(
        name=name,
        description=description,
        category="tool",
        version="0.1.0",
        owner="toolkit-ml-provenance",
        permission_scope=scope,
        input_schema=input_schema,
        output_schema=None,
        sandbox_requirement=None,
        aliases=None,
    )


_READ_ONLY_AUTO = AuthorityBoundary(
    scope=PermissionScope.READ_ONLY,
    approval=ApprovalPolicy.AUTO,
)

_WRITE_APPROVE = AuthorityBoundary(
    scope=PermissionScope.WORKSPACE_WRITE,
    approval=ApprovalPolicy.REQUIRE_APPROVAL,
)

# -- Per-command specs ---------------------------------------------------------

TOOLKIT_TOOL_SPECS: dict[str, ToolkitCommandSpec] = {
    "generate": ToolkitCommandSpec(
        command="generate",
        spec=_make_spec(
            name="generate",
            description=(
                "Generate a provenance manifest (JSON or CycloneDX) for a set of "
                "files matching glob patterns. Read-only analysis; writes only the "
                "output manifest file."
            ),
            scope=PermissionScope.WORKSPACE_WRITE,
            input_schema={
                "type": "object",
                "properties": {
                    "root": {"type": "string", "description": "Root directory"},
                    "out": {"type": "string", "description": "Output manifest path"},
                    "include": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Glob patterns for files to include",
                    },
                    "format": {"type": "string", "enum": ["json", "cyclonedx"]},
                },
                "required": ["out", "include"],
            },
        ),
        boundary=_WRITE_APPROVE,
    ),
    "keygen": ToolkitCommandSpec(
        command="keygen",
        spec=_make_spec(
            name="keygen",
            description=(
                "Generate an Ed25519 keypair for signing manifests. "
                "Writes private and public key files to disk. Requires approval."
            ),
            scope=PermissionScope.WORKSPACE_WRITE,
            input_schema={
                "type": "object",
                "properties": {
                    "private_key": {"type": "string", "description": "Output private key path"},
                    "public_key": {"type": "string", "description": "Output public key path"},
                },
                "required": ["private_key", "public_key"],
            },
        ),
        boundary=_WRITE_APPROVE,
    ),
    "sign": ToolkitCommandSpec(
        command="sign",
        spec=_make_spec(
            name="sign",
            description=(
                "Sign a provenance manifest and emit a detached signature JSON. "
                "Writes signature file to disk. Requires approval."
            ),
            scope=PermissionScope.WORKSPACE_WRITE,
            input_schema={
                "type": "object",
                "properties": {
                    "manifest": {"type": "string", "description": "Manifest JSON path"},
                    "private_key": {"type": "string", "description": "Private key PEM path"},
                    "out": {"type": "string", "description": "Output signature path"},
                },
                "required": ["manifest", "private_key"],
            },
        ),
        boundary=_WRITE_APPROVE,
    ),
    "verify": ToolkitCommandSpec(
        command="verify",
        spec=_make_spec(
            name="verify",
            description=(
                "Verify a provenance manifest against current files. "
                "Optionally verify a detached signature. Read-only; reports to stdout."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "manifest": {"type": "string", "description": "Manifest JSON path"},
                    "signature": {"type": "string", "description": "Signature JSON path (optional)"},
                    "out": {"type": "string"},
                },
                "required": ["manifest"],
            },
        ),
        boundary=_READ_ONLY_AUTO,
    ),
}


def get_tool_spec(command: str) -> ToolkitCommandSpec | None:
    """Return the ToolkitCommandSpec for a CLI subcommand, or None if unknown."""
    return TOOLKIT_TOOL_SPECS.get(command)


__all__ = ["TOOLKIT_TOOL_SPECS", "ToolkitCommandSpec", "get_tool_spec"]
