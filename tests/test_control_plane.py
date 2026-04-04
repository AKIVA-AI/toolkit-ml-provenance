"""
Tests for toolkit-ml-provenance control_plane adapter.

Coverage:
  - contracts: PermissionScope ordinal, AuthorityBoundary helpers
  - config: build_config_hierarchy (platform defaults, overrides, CLI)
  - tool_specs: TOOLKIT_TOOL_SPECS covers all 4 commands, get_tool_spec lookup
  - Optional framework import: _HAS_EXECUTION_CONTRACTS flag is a bool (no crash)
"""

from __future__ import annotations

from toolkit_ml_sbom.control_plane.config import (
    CONFIG_LEVELS,
    ToolkitConfigContract,
    build_config_hierarchy,
)
from toolkit_ml_sbom.control_plane.contracts import (
    _HAS_EXECUTION_CONTRACTS,
    ApprovalPolicy,
    AuthorityBoundary,
    PermissionScope,
    ToolSpec,
)
from toolkit_ml_sbom.control_plane.tool_specs import (
    TOOLKIT_TOOL_SPECS,
    get_tool_spec,
)

# -- contracts ----------------------------------------------------------------


class TestPermissionScope:
    def test_values_are_strings(self) -> None:
        assert PermissionScope.READ_ONLY.value == "read_only"
        assert PermissionScope.WORKSPACE_WRITE.value == "workspace_write"
        assert PermissionScope.FULL_ACCESS.value == "full_access"

    def test_ordinal_ascending(self) -> None:
        boundary = AuthorityBoundary(
            scope=PermissionScope.FULL_ACCESS, approval=ApprovalPolicy.AUTO
        )
        assert boundary.scope_allows(PermissionScope.READ_ONLY)

    def test_lower_does_not_satisfy_higher(self) -> None:
        boundary = AuthorityBoundary(scope=PermissionScope.READ_ONLY, approval=ApprovalPolicy.AUTO)
        assert not boundary.scope_allows(PermissionScope.WORKSPACE_WRITE)
        assert not boundary.scope_allows(PermissionScope.FULL_ACCESS)


class TestApprovalPolicy:
    def test_values_are_strings(self) -> None:
        assert ApprovalPolicy.AUTO.value == "auto"
        assert ApprovalPolicy.REQUIRE_APPROVAL.value == "require_approval"
        assert ApprovalPolicy.DENY.value == "deny"


class TestAuthorityBoundary:
    def test_is_denied(self) -> None:
        b = AuthorityBoundary(scope=PermissionScope.READ_ONLY, approval=ApprovalPolicy.DENY)
        assert b.is_denied()
        assert not b.needs_approval()

    def test_needs_approval(self) -> None:
        b = AuthorityBoundary(
            scope=PermissionScope.FULL_ACCESS, approval=ApprovalPolicy.REQUIRE_APPROVAL
        )
        assert b.needs_approval()
        assert not b.is_denied()

    def test_auto_neither(self) -> None:
        b = AuthorityBoundary(scope=PermissionScope.WORKSPACE_WRITE, approval=ApprovalPolicy.AUTO)
        assert not b.is_denied()
        assert not b.needs_approval()

    def test_sandbox_defaults_none(self) -> None:
        b = AuthorityBoundary(scope=PermissionScope.READ_ONLY, approval=ApprovalPolicy.AUTO)
        assert b.sandbox is None


class TestToolSpec:
    def test_construction(self) -> None:
        spec = ToolSpec(
            name="generate",
            description="test",
            category="tool",
            version="0.1.0",
            owner="toolkit-ml-provenance",
            permission_scope=PermissionScope.WORKSPACE_WRITE,
        )
        assert spec.name == "generate"
        assert spec.permission_scope == PermissionScope.WORKSPACE_WRITE
        assert spec.input_schema is None

    def test_repr_contains_name(self) -> None:
        spec = ToolSpec(
            name="verify",
            description="test",
            category="tool",
            version="0.1.0",
            owner="o",
            permission_scope=PermissionScope.READ_ONLY,
        )
        assert "verify" in repr(spec)


class TestFrameworkFlag:
    def test_flag_is_bool(self) -> None:
        assert isinstance(_HAS_EXECUTION_CONTRACTS, bool)


# -- config -------------------------------------------------------------------


class TestConfigLevels:
    def test_ordering(self) -> None:
        assert CONFIG_LEVELS["platform_default"] < CONFIG_LEVELS["toolkit_config"]
        assert CONFIG_LEVELS["toolkit_config"] < CONFIG_LEVELS["cli_override"]


class TestBuildConfigHierarchy:
    def test_defaults(self) -> None:
        cfg = build_config_hierarchy()
        assert cfg.toolkit_id == "TK-MP"
        assert cfg.toolkit_name == "toolkit-ml-provenance"
        assert cfg.log_format == "json"
        assert cfg.structured_logging is True
        assert cfg.hash_algorithm == "sha256"
        assert cfg.root_dir == "."

    def test_toolkit_config_overrides_defaults(self) -> None:
        cfg = build_config_hierarchy(
            toolkit_config={"hash_algorithm": "sha512", "log_format": "text"}
        )
        assert cfg.hash_algorithm == "sha512"
        assert cfg.log_format == "text"
        assert cfg.toolkit_id == "TK-MP"

    def test_cli_overrides_toolkit_config(self) -> None:
        cfg = build_config_hierarchy(
            toolkit_config={"output_format": "cyclonedx"},
            cli_overrides={"output_format": "json"},
        )
        assert cfg.output_format == "json"

    def test_unknown_keys_go_to_extra(self) -> None:
        cfg = build_config_hierarchy(toolkit_config={"custom_flag": True})
        assert cfg.extra.get("custom_flag") is True

    def test_returns_toolkit_config_contract(self) -> None:
        cfg = build_config_hierarchy()
        assert isinstance(cfg, ToolkitConfigContract)


# -- tool_specs ---------------------------------------------------------------


class TestToolkitToolSpecs:
    def test_all_four_commands_present(self) -> None:
        expected = {"generate", "keygen", "sign", "verify"}
        assert set(TOOLKIT_TOOL_SPECS.keys()) == expected

    def test_verify_is_read_only_auto(self) -> None:
        spec = TOOLKIT_TOOL_SPECS["verify"]
        assert spec.spec.permission_scope == PermissionScope.READ_ONLY
        assert spec.boundary.approval == ApprovalPolicy.AUTO

    def test_write_commands_require_approval(self) -> None:
        for cmd in ("generate", "keygen", "sign"):
            s = TOOLKIT_TOOL_SPECS[cmd]
            assert s.spec.permission_scope == PermissionScope.WORKSPACE_WRITE, cmd
            assert s.boundary.approval == ApprovalPolicy.REQUIRE_APPROVAL, cmd

    def test_boundary_scope_matches_spec_scope(self) -> None:
        for name, cmd_spec in TOOLKIT_TOOL_SPECS.items():
            assert cmd_spec.boundary.scope == cmd_spec.spec.permission_scope, name

    def test_no_sandbox_required(self) -> None:
        for name, cmd_spec in TOOLKIT_TOOL_SPECS.items():
            assert cmd_spec.spec.sandbox_requirement is None, name

    def test_generate_requires_out_and_include(self) -> None:
        schema = TOOLKIT_TOOL_SPECS["generate"].spec.input_schema
        assert schema is not None
        required = schema.get("required", [])
        assert "out" in required
        assert "include" in required

    def test_verify_requires_manifest(self) -> None:
        schema = TOOLKIT_TOOL_SPECS["verify"].spec.input_schema
        assert schema is not None
        assert "manifest" in schema.get("required", [])

    def test_command_name_matches_key(self) -> None:
        for key, cmd_spec in TOOLKIT_TOOL_SPECS.items():
            assert cmd_spec.command == key

    def test_owner_is_toolkit(self) -> None:
        for cmd_spec in TOOLKIT_TOOL_SPECS.values():
            assert cmd_spec.spec.owner == "toolkit-ml-provenance"


class TestGetToolSpec:
    def test_returns_spec_for_known_command(self) -> None:
        spec = get_tool_spec("generate")
        assert spec is not None
        assert spec.command == "generate"

    def test_returns_none_for_unknown_command(self) -> None:
        assert get_tool_spec("nonexistent") is None

    def test_returns_none_for_empty_string(self) -> None:
        assert get_tool_spec("") is None
