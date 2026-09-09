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


def test_task_requested_event_validates() -> None:
    validate_contract(
        "QueueEvent",
        {
            "schema_version": "1.0.0",
            "event_id": "evt:task-requested",
            "event_type": "task.requested",
            "aggregate_id": "task:00000001",
            "sequence": 0,
            "occurred_at": "2026-09-08T08:00:00Z",
            "correlation_id": "task:00000001",
            "causation_id": None,
            "payload": {
                "task_id": "task:00000001",
                "artifact_version_ids": ["artifact-version:00000001"],
            },
        },
    )


def test_static_analysis_result_validates_structured_tool_outcomes() -> None:
    validate_contract(
        "StaticAnalysisResult",
        {
            "schema_version": "1.0.0",
            "artifact_version_id": "artifact-version:source",
            "diagnostics": [
                {
                    "tool_name": "semgrep",
                    "rule_id": "python.lang.security.audit.eval-detected",
                    "severity": "high",
                    "message": "Use of eval on untrusted input",
                    "location": {
                        "artifact_version_id": "artifact-version:source",
                        "path": "src/app.py",
                        "start_line": 4,
                        "start_column": 5,
                        "end_line": 4,
                        "end_column": 18,
                    },
                    "cwe_ids": ["CWE-95"],
                    "properties": {"confidence": "high"},
                }
            ],
            "tool_runs": [
                {
                    "tool_name": "semgrep",
                    "tool_version": "1.130.0",
                    "status": "succeeded",
                    "exit_code": 0,
                    "reason": None,
                },
                {
                    "tool_name": "cppcheck",
                    "tool_version": None,
                    "status": "unavailable",
                    "exit_code": None,
                    "reason": "language_not_detected",
                },
            ],
            "created_at": "2026-09-08T13:10:00Z",
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


def test_pair_source_contracts_validate() -> None:
    location = {
        "artifact_version_id": "artifact-version:pair",
        "path": "src/main.c",
        "start_line": 1,
        "start_column": 1,
        "end_line": 1,
        "end_column": 10,
    }
    validate_contract(
        "PairFunction",
        {
            "schema_version": "1.0.0",
            "id": "pair-function:main",
            "artifact_version_id": "artifact-version:pair",
            "name": "main",
            "symbol": "main",
            "language": "c",
            "source_location": location,
            "binary_location": None,
            "signature": "main()",
            "attributes": {"kind": "function"},
        },
    )
    validate_contract(
        "PairEdge",
        {
            "schema_version": "1.0.0",
            "id": "pair-edge:call",
            "artifact_version_id": "artifact-version:pair",
            "source_node_id": "pair-node:main",
            "target_node_id": "pair-node:helper",
            "type": "call",
            "scope": "source",
            "confidence": 1.0,
            "evidence_id": None,
            "attributes": {},
        },
    )


def test_binary_analysis_contract_validates_normalized_addresses_and_tool_runs() -> None:
    validate_contract(
        "BinaryAnalysisResult",
        {
            "schema_version": "1.0.0",
            "artifact_version_id": "artifact-version:binary-source",
            "analyzed_artifact_version_id": "artifact-version:binary-source",
            "format": "elf",
            "architecture": "x86_64",
            "bits": 64,
            "endianness": "little",
            "image_base": 4194304,
            "entry_point": 4198400,
            "compiler": "GCC",
            "packer": None,
            "packed": False,
            "sections": [
                {
                    "name": ".text",
                    "virtual_address": 4198400,
                    "virtual_size": 7,
                    "file_offset": 512,
                    "file_size": 7,
                    "readable": True,
                    "writable": False,
                    "executable": True,
                }
            ],
            "functions": [
                {
                    "name": "main",
                    "address": 4198400,
                    "size": 7,
                    "file_offset": 512,
                    "attributes": {"source": "objdump"},
                }
            ],
            "instructions": [
                {
                    "address": 4198400,
                    "file_offset": 512,
                    "bytes": "55",
                    "mnemonic": "push",
                    "operands": "%rbp",
                    "function_name": "main",
                }
            ],
            "strings": [],
            "imports": [],
            "tool_runs": [
                {
                    "tool_name": "objdump",
                    "tool_version": "2.42",
                    "status": "succeeded",
                    "exit_code": 0,
                    "reason": None,
                    "raw_output": "bounded",
                }
            ],
            "status": "complete",
            "created_at": "2026-09-09T12:00:00Z",
        },
    )
