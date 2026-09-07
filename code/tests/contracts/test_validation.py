from __future__ import annotations

import pytest
from vulnweaver_contracts import (
    ContractValidationError,
    ensure_supported_version,
    validate_contract,
)


def _budget() -> dict[str, int]:
    return {
        "max_model_tokens": 1000,
        "cpu_millis": 1000,
        "memory_bytes": 64 * 1024 * 1024,
        "disk_bytes": 128 * 1024 * 1024,
        "max_tool_concurrency": 1,
        "max_dynamic_runs": 0,
        "timeout_seconds": 60,
    }


def test_job_requested_event_validates() -> None:
    validate_contract(
        "QueueEvent",
        {
            "schema_version": "1.0.0",
            "event_id": "evt:00000001",
            "event_type": "job.requested",
            "aggregate_id": "job:00000001",
            "sequence": 1,
            "occurred_at": "2026-09-07T08:00:00Z",
            "correlation_id": "task:00000001",
            "causation_id": None,
            "payload": {
                "job_id": "job:00000001",
                "task_id": "task:00000001",
                "job_kind": "source_analysis",
                "attempt": 0,
            },
        },
    )


def test_event_type_and_payload_shape_cannot_be_mixed() -> None:
    with pytest.raises(ContractValidationError):
        validate_contract(
            "QueueEvent",
            {
                "schema_version": "1.0.0",
                "event_id": "evt:00000001",
                "event_type": "job.requested",
                "aggregate_id": "job:00000001",
                "sequence": 1,
                "occurred_at": "2026-09-07T08:00:00Z",
                "correlation_id": "task:00000001",
                "causation_id": None,
                "payload": {
                    "task_id": "task:00000001",
                    "previous_status": "analyzing",
                    "status": "reviewing",
                    "result": None,
                },
            },
        )


def test_action_plan_rejects_an_arbitrary_command_field() -> None:
    with pytest.raises(ContractValidationError) as captured:
        validate_contract(
            "ActionPlan",
            {
                "schema_version": "1.0.0",
                "id": "plan:00000001",
                "task_id": "task:00000001",
                "agent_run_id": "run:00000001",
                "created_at": "2026-09-07T08:00:00Z",
                "steps": [
                    {
                        "step_id": "step:00000001",
                        "tool_name": "semgrep",
                        "tool_version": "1.0.0",
                        "input_refs": ["cas://sha256/input"],
                        "arguments": {"ruleset": "safe-default"},
                        "expected_output_types": ["sarif"],
                        "reason": "scan the registered source artifact",
                        "command": "sh -c arbitrary",
                    }
                ],
            },
        )
    assert "command" in str(captured.value)


def test_tool_spec_enforces_safe_filesystem_defaults() -> None:
    payload = {
        "schema_version": "1.0.0",
        "name": "semgrep",
        "version": "1.0.0",
        "image_digest": "sha256:" + "a" * 64,
        "risk_level": "low",
        "accepted_artifacts": ["source_archive"],
        "command_schema": {},
        "output_schema": {},
        "network_policy": {"access": "none", "allowed_hosts": []},
        "filesystem_policy": {
            "input_read_only": True,
            "isolated_output": True,
            "allow_host_paths": False,
        },
        "resource_limits": _budget(),
        "approval_required": False,
        "timeout_seconds": 60,
        "retry_policy": {
            "max_attempts": 2,
            "backoff_seconds": 1,
            "retryable_failure_kinds": ["timeout", "environment"],
        },
    }
    validate_contract("ToolSpec", payload)
    payload["filesystem_policy"] = {
        "input_read_only": False,
        "isolated_output": True,
        "allow_host_paths": True,
    }
    with pytest.raises(ContractValidationError):
        validate_contract("ToolSpec", payload)


def test_unknown_contract_version_is_rejected() -> None:
    ensure_supported_version("1.0.0")
    with pytest.raises(ContractValidationError):
        ensure_supported_version("2.0.0")
