"""Trusted ToolSpec and command profile for the combined AFL++/CASR image."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import PurePath
from typing import cast

from vulnweaver_contracts import (
    ArtifactKind,
    FailureKind,
    JsonObject,
    NetworkAccess,
    NetworkPolicy,
    ResourceBudget,
    RiskLevel,
    SchemaVersion,
    ToolSpec,
    validate_contract,
)
from vulnweaver_sandbox_runner import SandboxCommandProfile

AFL_CASR_TOOL_NAME = "afl-casr"
AFL_CASR_TOOL_VERSION = "1.0.0"
CASR_TOOL_NAME = "casr"
CASR_TOOL_VERSION = "2.12.0"
AFL_CASR_PROFILE = "afl-qemu-casr"
AFL_CASR_OUTPUT_NAMES = (
    "crash-manifest.json",
    "fuzz-summary.json",
    "minimized-inputs.tar",
)


def afl_casr_tool_spec(image_digest: str, resource_limits: ResourceBudget) -> ToolSpec:
    """Build the fixed policy definition after deployment resolves an image digest."""

    spec = ToolSpec(
        schema_version=SchemaVersion.VALUE_1_0_0,
        name=AFL_CASR_TOOL_NAME,
        version=AFL_CASR_TOOL_VERSION,
        image_digest=image_digest,
        risk_level=RiskLevel.HIGH,
        accepted_artifacts=[ArtifactKind.DERIVED],
        command_schema=cast(
            JsonObject,
            {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "profile",
                    "max_executions",
                    "max_duration_seconds",
                    "max_crashes",
                    "collect_coverage",
                ],
                "properties": {
                    "profile": {"type": "string", "const": AFL_CASR_PROFILE},
                    "max_executions": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 1_000_000_000,
                    },
                    "max_duration_seconds": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 86_400,
                    },
                    "max_crashes": {"type": "integer", "minimum": 1, "maximum": 10_000},
                    "collect_coverage": {"type": "boolean"},
                },
            },
        ),
        output_schema=cast(
            JsonObject,
            {
                "type": "object",
                "additionalProperties": False,
                "required": ["files"],
                "properties": {
                    "files": {
                        "type": "array",
                        "const": list(AFL_CASR_OUTPUT_NAMES),
                    }
                },
            },
        ),
        network_policy=cast(NetworkPolicy, {"access": NetworkAccess.NONE, "allowed_hosts": []}),
        filesystem_policy={
            "input_read_only": True,
            "isolated_output": True,
            "allow_host_paths": False,
        },
        resource_limits=resource_limits,
        approval_required=False,
        timeout_seconds=resource_limits["timeout_seconds"],
        retry_policy={
            "max_attempts": 2,
            "backoff_seconds": 5.0,
            "retryable_failure_kinds": [
                FailureKind.TIMEOUT,
                FailureKind.ENVIRONMENT,
                FailureKind.DEPENDENCY,
            ],
        },
    )
    validate_contract("ToolSpec", spec)
    return spec


def afl_casr_command_profile(
    image_ref: str,
    image_digest: str,
    *,
    executable: str = "vulnweaver-fuzz-entrypoint",
) -> SandboxCommandProfile:
    """Return the code-owned argv builder used by Sandbox Runner."""

    def build_argv(
        arguments: Mapping[str, object], input_path: PurePath, output_path: PurePath
    ) -> Sequence[str]:
        profile = _required_text(arguments, "profile")
        if profile != AFL_CASR_PROFILE:
            raise ValueError("unsupported AFL++/CASR profile")
        argv = [
            executable,
            "--profile",
            profile,
            "--input-bundle",
            str(input_path),
            "--output-dir",
            str(output_path),
            "--max-executions",
            str(_required_int(arguments, "max_executions")),
            "--max-duration-seconds",
            str(_required_int(arguments, "max_duration_seconds")),
            "--max-crashes",
            str(_required_int(arguments, "max_crashes")),
        ]
        collect_coverage = arguments.get("collect_coverage")
        if not isinstance(collect_coverage, bool):
            raise ValueError("collect_coverage must be a boolean")
        if collect_coverage:
            argv.append("--collect-coverage")
        return tuple(argv)

    return SandboxCommandProfile(
        tool_name=AFL_CASR_TOOL_NAME,
        tool_version=AFL_CASR_TOOL_VERSION,
        image_ref=image_ref,
        image_digest=image_digest,
        build_argv=build_argv,
    )


def _required_int(arguments: Mapping[str, object], key: str) -> int:
    value = arguments.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{key} must be a positive integer")
    return value


def _required_text(arguments: Mapping[str, object], key: str) -> str:
    value = arguments.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{key} must be non-empty text")
    return value
