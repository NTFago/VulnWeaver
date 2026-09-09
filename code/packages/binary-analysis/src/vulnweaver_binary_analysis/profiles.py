"""Code-owned ToolSpec and command profile for sandboxed binary analysis."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import PurePath
from typing import cast

from vulnweaver_contracts import (
    ArtifactKind,
    FailureKind,
    NetworkAccess,
    NetworkPolicy,
    ResourceBudget,
    RiskLevel,
    SchemaVersion,
    ToolSpec,
    validate_contract,
)
from vulnweaver_sandbox_runner import SandboxCommandProfile

BINARY_TOOL_NAME = "binary-facts"
BINARY_TOOL_VERSION = "1.0.0"
BINARY_OUTPUT_NAMES = ("binary-facts.json",)


def binary_tool_spec(image_digest: str, resource_limits: ResourceBudget) -> ToolSpec:
    spec = cast(
        ToolSpec,
        {
            "schema_version": SchemaVersion.VALUE_1_0_0,
            "name": BINARY_TOOL_NAME,
            "version": BINARY_TOOL_VERSION,
            "image_digest": image_digest,
            "risk_level": RiskLevel.LOW,
            "accepted_artifacts": [ArtifactKind.ELF, ArtifactKind.PE],
            "command_schema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["max_functions", "max_instructions", "max_pseudocode_functions"],
                "properties": {
                    "max_functions": {"type": "integer", "minimum": 1, "maximum": 20000},
                    "max_instructions": {"type": "integer", "minimum": 1, "maximum": 200000},
                    "max_pseudocode_functions": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 20000,
                    },
                },
            },
            "output_schema": {"type": "object"},
            "network_policy": cast(
                NetworkPolicy, {"access": NetworkAccess.NONE, "allowed_hosts": []}
            ),
            "filesystem_policy": {
                "input_read_only": True,
                "isolated_output": True,
                "allow_host_paths": False,
            },
            "resource_limits": resource_limits,
            "approval_required": False,
            "timeout_seconds": resource_limits["timeout_seconds"],
            "retry_policy": {
                "max_attempts": 1,
                "backoff_seconds": 0,
                "retryable_failure_kinds": [FailureKind.TIMEOUT],
            },
        },
    )
    validate_contract("ToolSpec", spec)
    return spec


def binary_command_profile(
    image_ref: str,
    image_digest: str,
    *,
    executable: str = "vulnweaver-binary-entrypoint",
) -> SandboxCommandProfile:
    def build_argv(
        arguments: Mapping[str, object], input_path: PurePath, output_path: PurePath
    ) -> Sequence[str]:
        max_functions = arguments.get("max_functions")
        max_instructions = arguments.get("max_instructions")
        max_pseudocode = arguments.get("max_pseudocode_functions")
        for name, value in (
            ("max_functions", max_functions),
            ("max_instructions", max_instructions),
            ("max_pseudocode_functions", max_pseudocode),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"binary argument {name} is invalid")
        return (
            executable,
            "--input",
            str(input_path),
            "--output-dir",
            str(output_path),
            "--max-functions",
            str(max_functions),
            "--max-instructions",
            str(max_instructions),
            "--max-pseudocode-functions",
            str(max_pseudocode),
        )

    return SandboxCommandProfile(
        tool_name=BINARY_TOOL_NAME,
        tool_version=BINARY_TOOL_VERSION,
        image_ref=image_ref,
        image_digest=image_digest,
        build_argv=build_argv,
    )
