from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import cast

import pytest
from vulnweaver_contracts import (
    ArtifactKind,
    FailureKind,
    FuzzRequest,
    FuzzStatus,
    SandboxRequest,
    StructuredFailure,
    ToolIdentity,
    validate_contract,
)
from vulnweaver_fuzzing import (
    CrashTriageError,
    CrashTriageService,
    FuzzBudgetGate,
    FuzzBudgetLimits,
    validate_fuzz_request,
)

TOOL = cast(
    ToolIdentity,
    {"name": "casr", "version": "2.12.0", "image_digest": "sha256:" + "a" * 64},
)
FUZZ_TOOL = cast(
    ToolIdentity,
    {"name": "afl-casr", "version": "1.0.0", "image_digest": "sha256:" + "a" * 64},
)


def entry(*, input_character: str = "b", address: str = "0x401000") -> dict[str, object]:
    return {
        "input_ref": "cas://sha256/" + input_character * 64,
        "input_digest": "sha256:" + input_character * 64,
        "signal": "SIGSEGV",
        "exit_code": -11,
        "stack_frames": [f"#0 {address} in parse_packet", "#1 0x402000 in main"],
        "stderr_ref": "cas://sha256/" + "c" * 64,
    }


def sandbox_request() -> SandboxRequest:
    return cast(
        SandboxRequest,
        {
            "schema_version": "1.0.0",
            "id": "sandbox-request:fuzz",
            "tool_name": "afl-fuzz",
            "tool_version": "4.0.0",
            "image_digest": "sha256:" + "a" * 64,
            "artifact_kind": ArtifactKind.ELF,
            "input_ref": "cas://sha256/" + "b" * 64,
            "arguments": {"profile": "safe"},
            "output_file_names": ["crashes.json"],
            "resource_budget": {
                "max_model_tokens": 0,
                "cpu_millis": 1000,
                "memory_bytes": 16 * 1024 * 1024,
                "disk_bytes": 1024 * 1024,
                "max_tool_concurrency": 1,
                "max_dynamic_runs": 1,
                "timeout_seconds": 30,
            },
            "timeout_seconds": 30,
        },
    )


def test_budget_gate_enforces_execution_crash_and_deadline_limits() -> None:
    started = datetime(2026, 9, 9, 8, 0, tzinfo=UTC)
    gate = FuzzBudgetGate(
        FuzzBudgetLimits(max_executions=2, max_duration_seconds=10, max_crashes=1),
        started,
    )

    assert gate.allow_execution(started + timedelta(seconds=1)) is True
    assert gate.allow_execution(started + timedelta(seconds=2)) is True
    assert gate.allow_execution(started + timedelta(seconds=3)) is False
    assert gate.allow_crash() is True
    assert gate.allow_crash() is False
    assert gate.expired(started + timedelta(seconds=10)) is True
    assert gate.allow_execution(started + timedelta(seconds=10)) is False


def test_fuzz_request_validator_checks_nested_sandbox_budget() -> None:
    value = cast(
        dict[str, object],
        {
            "schema_version": "1.0.0",
            "id": "fuzz-request:test",
            "job_id": "job:fuzz",
            "sandbox_request": sandbox_request(),
            "artifact_version_id": "artifact-version:fuzz",
            "seed_refs": ["cas://sha256/" + "b" * 64],
            "max_executions": 100,
            "max_duration_seconds": 60,
            "max_crashes": 4,
            "collect_coverage": True,
        },
    )
    limits = validate_fuzz_request(cast("FuzzRequest", value))
    assert limits.max_executions == 100
    assert limits.max_duration_seconds == 60

    value["sandbox_request"] = cast(
        SandboxRequest,
        {**sandbox_request(), "id": "fuzz-request:test"},
    )
    with pytest.raises(CrashTriageError, match="distinct IDs"):
        validate_fuzz_request(cast("FuzzRequest", value))

    value["sandbox_request"] = sandbox_request()
    value["max_duration_seconds"] = 20
    with pytest.raises(CrashTriageError, match="timeout"):
        validate_fuzz_request(cast("FuzzRequest", value))


def test_crash_triage_normalizes_frames_and_clusters_addresses() -> None:
    service = CrashTriageService(
        FuzzBudgetLimits(max_executions=10, max_duration_seconds=60, max_crashes=4)
    )
    first = service.ingest(
        entry(address="0x401000"),
        artifact_version_id="artifact-version:fuzz",
        fuzz_tool=FUZZ_TOOL,
        tool=TOOL,
        created_at="2026-09-09T08:00:00Z",
    )
    second = service.ingest(
        entry(input_character="d", address="0x401100"),
        artifact_version_id="artifact-version:fuzz",
        fuzz_tool=FUZZ_TOOL,
        tool=TOOL,
        created_at="2026-09-09T08:00:01Z",
    )

    assert first is not None and second is not None
    assert first["stack_hash"] == second["stack_hash"]
    assert first["id"] != second["id"]
    assert first["stack_frames"] == ["0x401000 in parse_packet", "0x402000 in main"]
    assert set(service.cluster(first["stack_hash"])) == {first["id"], second["id"]}
    assert len(service.records()) == 2

    replay = service.ingest(
        entry(address="0x401000"),
        artifact_version_id="artifact-version:fuzz",
        fuzz_tool=FUZZ_TOOL,
        tool=TOOL,
        created_at="2026-09-09T08:01:00Z",
    )
    assert replay == first


def test_ingest_many_is_idempotent_and_keeps_first_seen_records() -> None:
    service = CrashTriageService(
        FuzzBudgetLimits(max_executions=10, max_duration_seconds=60, max_crashes=4)
    )
    records = service.ingest_many(
        [entry(), entry(), entry(input_character="d")],
        artifact_version_id="artifact-version:fuzz",
        fuzz_tool=FUZZ_TOOL,
        tool=TOOL,
        created_at="2026-09-09T08:00:00Z",
    )

    assert len(records) == 2
    assert {item["id"] for item in records} == {item["id"] for item in service.records()}


def test_ingest_many_rejects_oversized_manifests() -> None:
    service = CrashTriageService(
        FuzzBudgetLimits(
            max_executions=10,
            max_duration_seconds=60,
            max_crashes=2,
            max_manifest_entries=2,
        )
    )

    with pytest.raises(CrashTriageError, match="manifest"):
        service.ingest_many(
            [entry(), entry(), entry()],
            artifact_version_id="artifact-version:fuzz",
            fuzz_tool=FUZZ_TOOL,
            tool=TOOL,
            created_at="2026-09-09T08:00:00Z",
        )


def test_stack_hash_does_not_treat_hexadecimal_symbol_names_as_addresses() -> None:
    service = CrashTriageService(
        FuzzBudgetLimits(max_executions=10, max_duration_seconds=60, max_crashes=2)
    )
    first = service.ingest(
        {**entry(), "stack_frames": ["#0 deadbeef in parser"]},
        artifact_version_id="artifact-version:fuzz",
        fuzz_tool=FUZZ_TOOL,
        tool=TOOL,
        created_at="2026-09-09T08:00:00Z",
    )
    second = service.ingest(
        {
            **entry(input_character="d"),
            "stack_frames": ["#0 feedface in parser"],
        },
        artifact_version_id="artifact-version:fuzz",
        fuzz_tool=FUZZ_TOOL,
        tool=TOOL,
        created_at="2026-09-09T08:00:01Z",
    )

    assert first is not None and second is not None
    assert first["stack_hash"] != second["stack_hash"]


def test_crash_triage_enforces_limits_and_rejects_malformed_entries() -> None:
    service = CrashTriageService(
        FuzzBudgetLimits(
            max_executions=10,
            max_duration_seconds=60,
            max_crashes=1,
            max_stack_frames=2,
            max_frame_chars=32,
        )
    )
    service.ingest(
        entry(),
        artifact_version_id="artifact-version:fuzz",
        fuzz_tool=FUZZ_TOOL,
        tool=TOOL,
        created_at="2026-09-09T08:00:00Z",
    )
    assert (
        service.ingest(
            entry(input_character="d"),
            artifact_version_id="artifact-version:fuzz",
            fuzz_tool=FUZZ_TOOL,
            tool=TOOL,
            created_at="2026-09-09T08:00:01Z",
        )
        is None
    )
    with pytest.raises(CrashTriageError, match="canonical sha256"):
        service.ingest(
            {**entry(), "input_digest": "not-a-digest"},
            artifact_version_id="artifact-version:fuzz",
            fuzz_tool=FUZZ_TOOL,
            tool=TOOL,
            created_at="2026-09-09T08:00:00Z",
        )
    with pytest.raises(CrashTriageError, match="stack frame count"):
        service.ingest(
            {**entry(), "stack_frames": ["one", "two", "three"]},
            artifact_version_id="artifact-version:fuzz-2",
            fuzz_tool=FUZZ_TOOL,
            tool=TOOL,
            created_at="2026-09-09T08:00:00Z",
        )
    with pytest.raises(CrashTriageError, match="stderr_ref"):
        service.ingest(
            {
                **entry(input_character="e"),
                "stderr_ref": "cas://sha256/not-canonical",
            },
            artifact_version_id="artifact-version:fuzz-3",
            fuzz_tool=FUZZ_TOOL,
            tool=TOOL,
            created_at="2026-09-09T08:00:00Z",
        )


def test_fuzz_result_is_versioned_and_reports_structured_failure() -> None:
    service = CrashTriageService(
        FuzzBudgetLimits(max_executions=10, max_duration_seconds=60, max_crashes=2)
    )
    service.set_execution_count(3)
    failure = cast(
        StructuredFailure,
        {
            "code": "fuzz.tool_failed",
            "kind": FailureKind.TOOL,
            "message": "fuzz tool failed",
            "retryable": False,
            "details": {"exit_code": 1},
        },
    )
    result = service.build_result(
        "job:fuzz",
        status=FuzzStatus.PARTIAL,
        coverage_percent=42.5,
        created_at="2026-09-09T08:00:00Z",
        failure=failure,
    )

    validate_contract("FuzzResult", result)
    assert result["executions"] == 3
    assert result["coverage_percent"] == 42.5
    assert result["failure"] is not None
    assert result["failure"]["code"] == "fuzz.tool_failed"

    with pytest.raises(CrashTriageError, match="require a structured failure"):
        service.build_result(
            "job:fuzz",
            status=FuzzStatus.FAILED,
            coverage_percent=None,
            created_at="2026-09-09T08:00:00Z",
        )

    with pytest.raises(CrashTriageError, match="cannot include a failure"):
        service.build_result(
            "job:fuzz",
            status=FuzzStatus.SUCCEEDED,
            coverage_percent=100.0,
            created_at="2026-09-09T08:00:00Z",
            failure=failure,
        )
