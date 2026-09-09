"""Code-owned ToolSpec and command profile for Proof execution."""

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

PROOF_TOOL_NAME = "proof-tool"
PROOF_TOOL_VERSION = "1.0.0"


def proof_tool_spec(image_digest: str, resource_limits: ResourceBudget) -> ToolSpec:
    spec = cast(
        ToolSpec,
        {
            "schema_version": SchemaVersion.VALUE_1_0_0,
            "name": PROOF_TOOL_NAME,
            "version": PROOF_TOOL_VERSION,
            "image_digest": image_digest,
            "risk_level": RiskLevel.HIGH,
            "accepted_artifacts": [ArtifactKind.DERIVED],
            "command_schema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["finding_id", "kind"],
                "properties": {
                    "finding_id": {"type": "string", "minLength": 1, "maxLength": 128},
                    "kind": {"type": "string", "enum": ["proof_of_concept", "exploit"]},
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


def proof_command_profile(
    image_ref: str,
    image_digest: str,
    *,
    executable: str = "vulnweaver-proof-entrypoint",
) -> SandboxCommandProfile:
    def build_argv(
        arguments: Mapping[str, object], input_path: PurePath, output_path: PurePath
    ) -> Sequence[str]:
        finding_id = arguments.get("finding_id")
        kind = arguments.get("kind")
        if not isinstance(finding_id, str) or not finding_id or not isinstance(kind, str):
            raise ValueError("proof arguments are invalid")
        if kind not in {"proof_of_concept", "exploit"}:
            raise ValueError("proof kind is unsupported")
        return (
            executable,
            "--script",
            str(input_path),
            "--finding-id",
            finding_id,
            "--kind",
            kind,
            "--output-dir",
            str(output_path),
        )

    return SandboxCommandProfile(
        tool_name=PROOF_TOOL_NAME,
        tool_version=PROOF_TOOL_VERSION,
        image_ref=image_ref,
        image_digest=image_digest,
        build_argv=build_argv,
    )
