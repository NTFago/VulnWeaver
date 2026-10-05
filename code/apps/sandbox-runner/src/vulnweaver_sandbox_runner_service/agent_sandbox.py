"""Code-owned ToolSpec and command profile for the agent sandbox command tool.

The audit agent plans one shell command per step; the runner executes it inside
a one-shot, network-disabled, non-root container built from the pinned proof
image (ADR-038). The command string is a schema-validated ToolSpec argument,
never a container-level instruction: argv is constructed here, argv[0] is
/bin/sh, and the model only fills the ``-c`` operand. Isolation properties are
the runtime's mandatory ones and are not configurable per request.
"""

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
from vulnweaver_proof import AGENT_SANDBOX_TOOL_NAME, AGENT_SANDBOX_TOOL_VERSION
from vulnweaver_sandbox_runner import SandboxCommandProfile

# The trusted profile prefixes "cd /work && " before the model's command; the
# combined operand must stay under the runtime's 4096-char argv element bound.
# Longer scripts bootstrap themselves: the command can write a file into /work
# (newlines escaped) and execute it in a second statement.
_MAX_COMMAND_CHARS = 3600

# The sample the agent anchored on is materialized read-only at /input/input.bin.
WORKDIR = "/work"
INPUT_PATH = "/input/input.bin"


def agent_sandbox_tool_spec(image_digest: str, resource_limits: ResourceBudget) -> ToolSpec:
    spec = cast(
        ToolSpec,
        {
            "schema_version": SchemaVersion.VALUE_1_0_0,
            "name": AGENT_SANDBOX_TOOL_NAME,
            "version": AGENT_SANDBOX_TOOL_VERSION,
            "image_digest": image_digest,
            "risk_level": RiskLevel.HIGH,
            "accepted_artifacts": [kind.value for kind in ArtifactKind],
            "command_schema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["command"],
                "properties": {
                    "command": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": _MAX_COMMAND_CHARS,
                        "pattern": "^[^\\x00-\\x1f]*$",
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


def agent_sandbox_command_profile(
    image_ref: str,
    image_digest: str,
) -> SandboxCommandProfile:
    def build_argv(
        arguments: Mapping[str, object], input_path: PurePath, output_path: PurePath
    ) -> Sequence[str]:
        command = arguments.get("command")
        if not isinstance(command, str) or not command:
            raise ValueError("agent sandbox command is required")
        if len(command) > _MAX_COMMAND_CHARS:
            raise ValueError("agent sandbox command exceeds its length bound")
        if any(char in command for char in ("\x00", "\n", "\r")):
            raise ValueError("agent sandbox command must not contain control characters")
        return (
            "/bin/sh",
            "-c",
            f"cd {WORKDIR} && {command}",
        )

    return SandboxCommandProfile(
        tool_name=AGENT_SANDBOX_TOOL_NAME,
        tool_version=AGENT_SANDBOX_TOOL_VERSION,
        image_ref=image_ref,
        image_digest=image_digest,
        build_argv=build_argv,
    )
