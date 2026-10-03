from __future__ import annotations

import asyncio
import io
import json
from typing import Any, cast

from vulnweaver_artifact_store import LocalContentAddressedStore
from vulnweaver_contracts import (
    ArtifactKind,
    FindingStatus,
    Job,
    JobKind,
    JobStatus,
    PocKind,
    ProofRequest,
    ResourceBudget,
    SandboxResult,
    SandboxStatus,
)
from vulnweaver_persistence import Database
from vulnweaver_proof import (
    ProofExecutionService,
    ProofJobExecutor,
    build_execution_bundle,
)

IMAGE_DIGEST = "sha256:" + "a" * 64


def _request() -> ProofRequest:
    return cast(
        ProofRequest,
        {
            "schema_version": "1.0.0",
            "id": "poc:proof-test",
            "job_id": "job:proof-test",
            "finding_id": "finding:proof-test",
            "script_ref": "cas://" + "b" * 64,
            "image_digest": IMAGE_DIGEST,
            "permission_mode": "request_permission",
            "resource_budget": {
                "max_model_tokens": 0,
                "cpu_millis": 1000,
                "memory_bytes": 1048576,
                "disk_bytes": 1048576,
                "max_tool_concurrency": 1,
                "max_dynamic_runs": 1,
                "timeout_seconds": 30,
            },
            "timeout_seconds": 20,
        },
    )


def _result(status: SandboxStatus) -> SandboxResult:
    return cast(
        SandboxResult,
        {
            "schema_version": "1.0.0",
            "request_id": "sandbox-request:poc:proof-test",
            "status": status,
            "exit_code": 0 if status is SandboxStatus.SUCCEEDED else None,
            "stdout_ref": "cas://stdout" if status is SandboxStatus.SUCCEEDED else None,
            "stderr_ref": None,
            "outputs": [],
            "resource_usage": {
                "duration_millis": 10,
                "cpu_millis": 5,
                "memory_bytes": 1024,
                "output_bytes": 0,
            },
            "failure": None,
        },
    )


class _FakeSandbox:
    def __init__(self, result: SandboxResult) -> None:
        self.result = result
        self.requests: list[object] = []

    async def run(self, request: object, cancellation: asyncio.Event) -> SandboxResult:
        self.requests.append(request)
        return self.result


def _job(**kwargs: object) -> Job:
    return cast(
        Job,
        {
            "schema_version": "1.0.0",
            "id": "job:proof-test",
            "task_id": "task:proof-test",
            "kind": kwargs.get("kind", JobKind.PROOF),
            "input_refs": [],
            "status": JobStatus.QUEUED,
            "idempotency_key": "proof-test",
            "resource_budget": _request()["resource_budget"],
            "retry_policy": {
                "max_attempts": 1,
                "backoff_seconds": 1,
                "retryable_failure_kinds": [],
            },
            "attempt": 0,
            "lease": None,
            "failure": None,
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:00:00+00:00",
            **({"arguments": kwargs["arguments"]} if "arguments" in kwargs else {}),
        },
    )


def test_worker_adapter_rejects_non_proof_jobs_without_database_access() -> None:
    executor = ProofJobExecutor(cast(Database, None), cast(ProofExecutionService, None))
    result = asyncio.run(executor.execute(_job(kind=JobKind.REVIEW), asyncio.Event()))
    assert result["status"] == JobStatus.FAILED
    assert result["failure"]["code"] == "proof.invalid_job_kind"


def test_worker_adapter_rejects_missing_structured_request_without_database_access() -> None:
    executor = ProofJobExecutor(cast(Database, None), cast(ProofExecutionService, None))
    result = asyncio.run(executor.execute(_job(), asyncio.Event()))
    assert result["status"] == JobStatus.FAILED
    assert result["failure"]["code"] == "proof.request_required"


def test_exploit_is_policy_denied_before_sandbox_for_unconfirmed_finding() -> None:
    sandbox = _FakeSandbox(_result(SandboxStatus.SUCCEEDED))
    service = ProofExecutionService(sandbox, tool_name="proof", tool_version="1.0.0")

    run = asyncio.run(
        service.run(
            _request(),
            finding_status=FindingStatus.CANDIDATE,
            exploit_validation_enabled=True,
            cancellation=asyncio.Event(),
            kind=PocKind.EXPLOIT,
        )
    )

    assert run.observation is None
    assert run.poc["result"] == "policy_denied"
    assert run.poc["status"] == "failed"
    assert sandbox.requests == []


def test_proof_binds_script_and_pinned_policy_to_sandbox() -> None:
    sandbox = _FakeSandbox(_result(SandboxStatus.SUCCEEDED))
    service = ProofExecutionService(sandbox, tool_name="proof", tool_version="1.0.0")

    run = asyncio.run(
        service.run(
            _request(),
            finding_status=FindingStatus.CONFIRMED,
            exploit_validation_enabled=False,
            cancellation=asyncio.Event(),
        )
    )

    request = cast(dict[str, object], sandbox.requests[0])
    assert request["input_ref"] == _request()["script_ref"]
    assert request["image_digest"] == IMAGE_DIGEST
    assert request["tool_name"] == "proof"
    # Tool success without a trusted observation still proves nothing.
    assert run.observation is None
    assert run.poc["result"] == "inconclusive"
    assert run.poc["status"] == "completed"
    assert run.poc["run_log_ref"] == "cas://stdout"


def test_sandbox_request_forwards_the_budget_without_clamping() -> None:
    """Budgets are inert (ADR-025): oversized values pass through instead of clamping."""

    sandbox = _FakeSandbox(_result(SandboxStatus.SUCCEEDED))
    service = ProofExecutionService(sandbox, tool_name="proof", tool_version="1.0.0")
    request = _request()
    request["resource_budget"] = cast(
        ResourceBudget,
        {
            **request["resource_budget"],
            "cpu_millis": 8000,
            "memory_bytes": 3 * 1024**3,
            "disk_bytes": 10 * 1024**3,
            "timeout_seconds": 3600,
        },
    )
    request["timeout_seconds"] = 3600

    asyncio.run(
        service.run(
            request,
            finding_status=FindingStatus.CONFIRMED,
            exploit_validation_enabled=False,
            cancellation=asyncio.Event(),
        )
    )

    sandbox_request = cast(dict[str, object], sandbox.requests[0])
    budget = cast(dict[str, int], sandbox_request["resource_budget"])
    assert budget["cpu_millis"] == 8000
    assert budget["memory_bytes"] == 3 * 1024**3
    assert budget["disk_bytes"] == 10 * 1024**3
    assert sandbox_request["timeout_seconds"] == 3600


def test_sandbox_timeout_and_cancel_are_not_reported_as_exploitable() -> None:
    for status, expected in (
        (SandboxStatus.TIMED_OUT, "timeout"),
        (SandboxStatus.CANCELLED, "environment_error"),
    ):
        sandbox = _FakeSandbox(_result(status))
        service = ProofExecutionService(sandbox, tool_name="proof", tool_version="1.0.0")
        run = asyncio.run(
            service.run(
                _request(),
                finding_status=FindingStatus.CONFIRMED,
                exploit_validation_enabled=True,
                cancellation=asyncio.Event(),
            )
        )
        assert run.poc["result"] == expected
        assert run.poc["status"] in {"failed", "cancelled"}


def _observation(verdict: str, finding_id: str = "finding:proof-test") -> dict[str, object]:
    verified = verdict == "verified_trigger"
    runs = [
        {
            "role": "control", "input_name": "0000", "exit_code": 0, "signal": None,
            "duration_millis": 3, "target_frames": False, "timed_out": False,
        },
        {
            "role": "trigger", "input_name": "0000", "exit_code": 10 if verified else 0,
            "signal": None, "duration_millis": 8, "target_frames": verified,
            "timed_out": False,
        },
    ]
    if verified:
        runs.extend(
            {
                "role": "replay", "input_name": "0000", "exit_code": 10, "signal": None,
                "duration_millis": 7, "target_frames": True, "timed_out": False,
            }
            for _ in range(2)
        )
    return {
        "schema_version": "1.0.0",
        "id": "observation:proof-test",
        "kind": "proof_of_concept",
        "finding_id": finding_id,
        "verdict": verdict,
        "verdict_reasons": (
            ["target_exception_attributed", "control_input_clean", "replay_stable"]
            if verified else ["no_trigger_observed"]
        ),
        "driver_digest": "sha256:" + "c" * 64,
        "target_binding": {
            "artifact_id": "artifact:proof-test",
            "version_id": "artifact-version:proof-test",
            "artifact_kind": "source_archive",
            "digest": "sha256:" + "d" * 64,
        },
        "inputs": [{"name": "inputs/0000", "digest": "sha256:" + "e" * 64, "size_bytes": 4}],
        "controls": [{"name": "controls/0000", "digest": "sha256:" + "f" * 64, "size_bytes": 4}],
        "runs": runs,
        "trigger_runs": 3 if verified else 0,
        "replay_runs": 2 if verified else 0,
        "untrusted_claims": None,
        "verifier": {"name": "proof-entrypoint", "version": "2.0.0", "image_digest": None},
        "created_at": "2026-10-03T08:00:00Z",
    }


def _bundle_for_request(
    store: LocalContentAddressedStore, request: ProofRequest
) -> dict[str, object]:
    target = store.put_stream(
        io.BytesIO(b"def parse(value):\n    raise ValueError('target exception')\n"),
        max_bytes=1024,
    )
    driver = store.put_stream(
        io.BytesIO(b'{"target_callable":"parse","input_mode":"text"}'), max_bytes=1024
    )
    crafted = store.put_stream(io.BytesIO(b"trigger"), max_bytes=1024)
    control = store.put_stream(io.BytesIO(b"control"), max_bytes=1024)
    bundle = build_execution_bundle(
        store,
        bundle_id="execution-bundle:proof-test",
        finding_id=request["finding_id"],
        driver_ref=driver.object_ref,
        target_binding={
            "artifact_id": "artifact:proof-test",
            "version_id": "artifact-version:proof-test",
            "artifact_kind": ArtifactKind.SOURCE_ARCHIVE,
            "digest": target.digest,
        },
        target_ref=target.object_ref,
        input_refs=[crafted.object_ref],
        control_refs=[control.object_ref],
        created_at="2026-10-03T08:00:00Z",
    )
    request["script_ref"] = bundle.stored.object_ref
    return {
        "driver_digest": bundle.manifest["driver"]["digest"],
        "target_binding": dict(bundle.manifest["target_binding"]),
        "inputs": [dict(member) for member in bundle.manifest["inputs"]],
        "controls": [dict(member) for member in bundle.manifest["controls"]],
    }


def _bind_observation_to_bundle(
    observation: dict[str, object], bundle_fields: dict[str, object]
) -> None:
    observation.update(bundle_fields)


class _ReportSandbox:
    def __init__(self, outputs: list[dict[str, object]]) -> None:
        self.outputs = outputs

    async def run(self, request: object, cancellation: asyncio.Event) -> SandboxResult:
        return cast(
            SandboxResult,
            {
                "schema_version": "1.0.0",
                "request_id": "sandbox-request:poc:proof-test",
                "status": SandboxStatus.SUCCEEDED,
                "exit_code": 0,
                "stdout_ref": "cas://stdout",
                "stderr_ref": None,
                "outputs": self.outputs,
                "resource_usage": {
                    "duration_millis": 10,
                    "cpu_millis": 5,
                    "memory_bytes": 1024,
                    "output_bytes": 0,
                },
                "failure": None,
            },
        )


def test_verified_target_exception_maps_to_inconclusive(tmp_path: object) -> None:
    store = LocalContentAddressedStore(cast(Any, tmp_path))
    request = _request()
    fields = _bundle_for_request(store, request)
    observation = _observation("verified_trigger")
    _bind_observation_to_bundle(observation, fields)
    payload = json.dumps(observation).encode("utf-8")
    report = store.put_stream(io.BytesIO(payload), max_bytes=65536)
    service = ProofExecutionService(
        _ReportSandbox([{"path": "execution-report.json",
                         "object_ref": report.object_ref,
                         "digest": report.digest,
                         "size_bytes": report.size_bytes}]),
        tool_name="proof",
        tool_version="1.0.0",
        store=store,
    )

    run = asyncio.run(
        service.run(
            request,
            finding_status=FindingStatus.CONFIRMED,
            exploit_validation_enabled=False,
            cancellation=asyncio.Event(),
            expected_target_binding=cast(
                Any, observation["target_binding"]
            ),
        )
    )

    assert run.poc["result"] == "inconclusive"
    assert run.poc["status"] == "completed"
    assert isinstance(run.observation, dict)
    assert run.observation["verdict"] == "verified_trigger"


def test_rejected_observation_maps_to_not_exploitable(tmp_path: object) -> None:
    store = LocalContentAddressedStore(cast(Any, tmp_path))
    request = _request()
    fields = _bundle_for_request(store, request)
    observation = _observation("rejected_under_test_conditions")
    _bind_observation_to_bundle(observation, fields)
    payload = json.dumps(observation).encode("utf-8")
    report = store.put_stream(io.BytesIO(payload), max_bytes=65536)
    service = ProofExecutionService(
        _ReportSandbox([{"path": "execution-report.json",
                         "object_ref": report.object_ref,
                         "digest": report.digest,
                         "size_bytes": report.size_bytes}]),
        tool_name="proof",
        tool_version="1.0.0",
        store=store,
    )

    run = asyncio.run(
        service.run(
            request,
            finding_status=FindingStatus.CONFIRMED,
            exploit_validation_enabled=False,
            cancellation=asyncio.Event(),
            expected_target_binding=cast(
                Any, observation["target_binding"]
            ),
        )
    )

    assert run.poc["result"] == "not_exploitable_under_environment"
    assert run.poc["status"] == "completed"


def test_report_bound_to_another_finding_is_ignored(tmp_path: object) -> None:
    store = LocalContentAddressedStore(cast(Any, tmp_path))
    request = _request()
    fields = _bundle_for_request(store, request)
    observation = _observation("verified_trigger", finding_id="finding:other")
    _bind_observation_to_bundle(observation, fields)
    payload = json.dumps(observation).encode()
    report = store.put_stream(io.BytesIO(payload), max_bytes=65536)
    service = ProofExecutionService(
        _ReportSandbox([{"path": "execution-report.json",
                         "object_ref": report.object_ref,
                         "digest": report.digest,
                         "size_bytes": report.size_bytes}]),
        tool_name="proof",
        tool_version="1.0.0",
        store=store,
    )

    run = asyncio.run(
        service.run(
            request,
            finding_status=FindingStatus.CONFIRMED,
            exploit_validation_enabled=False,
            cancellation=asyncio.Event(),
            expected_target_binding=cast(
                Any, observation["target_binding"]
            ),
        )
    )

    assert run.observation is None


def test_bundle_for_another_finding_is_not_reusable(tmp_path: object) -> None:
    store = LocalContentAddressedStore(cast(Any, tmp_path))
    request = _request()
    fields = _bundle_for_request(store, request)
    observation = _observation("verified_trigger")
    _bind_observation_to_bundle(observation, fields)
    report = store.put_stream(
        io.BytesIO(json.dumps(observation).encode()), max_bytes=65536
    )
    request["finding_id"] = "finding:other"
    service = ProofExecutionService(
        _ReportSandbox([{"path": "execution-report.json", "object_ref": report.object_ref,
                         "digest": report.digest, "size_bytes": report.size_bytes}]),
        tool_name="proof", tool_version="1.0.0", store=store,
    )

    run = asyncio.run(
        service.run(
            request,
            finding_status=FindingStatus.CONFIRMED,
            exploit_validation_enabled=False,
            cancellation=asyncio.Event(),
            expected_target_binding=cast(Any, observation["target_binding"]),
        )
    )

    assert run.observation is None
    assert run.poc["result"] == "inconclusive"


def test_bundle_observation_target_binding_mismatch_is_ignored(tmp_path: object) -> None:
    store = LocalContentAddressedStore(cast(Any, tmp_path))
    request = _request()
    fields = _bundle_for_request(store, request)
    observation = _observation("verified_trigger")
    _bind_observation_to_bundle(observation, fields)
    report = store.put_stream(
        io.BytesIO(json.dumps(observation).encode()), max_bytes=65536
    )
    expected_binding = dict(observation["target_binding"])
    expected_binding["digest"] = "sha256:" + "f" * 64
    service = ProofExecutionService(
        _ReportSandbox([{"path": "execution-report.json", "object_ref": report.object_ref,
                         "digest": report.digest, "size_bytes": report.size_bytes}]),
        tool_name="proof", tool_version="1.0.0", store=store,
    )

    run = asyncio.run(
        service.run(
            request,
            finding_status=FindingStatus.CONFIRMED,
            exploit_validation_enabled=False,
            cancellation=asyncio.Event(),
            expected_target_binding=cast(Any, expected_binding),
        )
    )

    assert run.observation is None
    assert run.poc["result"] == "inconclusive"


def test_observation_run_counters_must_match_recorded_runs(tmp_path: object) -> None:
    store = LocalContentAddressedStore(cast(Any, tmp_path))
    request = _request()
    fields = _bundle_for_request(store, request)
    observation = _observation("verified_trigger")
    observation["trigger_runs"] = 2
    _bind_observation_to_bundle(observation, fields)
    report = store.put_stream(
        io.BytesIO(json.dumps(observation).encode()), max_bytes=65536
    )
    service = ProofExecutionService(
        _ReportSandbox([{"path": "execution-report.json", "object_ref": report.object_ref,
                         "digest": report.digest, "size_bytes": report.size_bytes}]),
        tool_name="proof", tool_version="1.0.0", store=store,
    )

    run = asyncio.run(
        service.run(
            request,
            finding_status=FindingStatus.CONFIRMED,
            exploit_validation_enabled=False,
            cancellation=asyncio.Event(),
            expected_target_binding=cast(Any, observation["target_binding"]),
        )
    )

    assert run.observation is None
    assert run.poc["result"] == "inconclusive"
