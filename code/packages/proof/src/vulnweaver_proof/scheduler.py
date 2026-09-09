"""Durable scheduling for policy-gated proof jobs."""

from __future__ import annotations

from typing import cast

from vulnweaver_contracts import (
    FailureKind,
    Job,
    JobKind,
    JobRequestedEvent,
    JobStatus,
    JsonObject,
    PocKind,
    ProofRequest,
    RetryPolicy,
    SchemaVersion,
    ToolIdentity,
    validate_contract,
)
from vulnweaver_persistence import Repositories

from .validation import ensure_script_ref_belongs_to_project


class ProofJobScheduler:
    """Create one durable proof Job for a validated ProofRequest."""

    def __init__(
        self,
        *,
        tool: ToolIdentity,
        retry_policy: RetryPolicy | None = None,
    ) -> None:
        self._tool = tool
        self._retry_policy = retry_policy or RetryPolicy(
            max_attempts=2,
            backoff_seconds=5.0,
            retryable_failure_kinds=[FailureKind.TIMEOUT, FailureKind.ENVIRONMENT],
        )

    async def schedule(
        self, repositories: Repositories, request: ProofRequest, *, kind: PocKind
    ) -> Job:
        validate_contract("ProofRequest", request)
        finding = await repositories.findings.get(request["finding_id"])
        task = await repositories.tasks.get(finding["task_id"], for_update=True)
        project = await repositories.projects.get(task["project_id"])
        if not project["exploit_validation_enabled"] and kind is PocKind.EXPLOIT:
            raise PermissionError("project has disabled exploit validation")
        await ensure_script_ref_belongs_to_project(
            repositories, script_ref=request["script_ref"], project_id=project["id"]
        )

        created_at = task["updated_at"]
        job = Job(
            schema_version=SchemaVersion.VALUE_1_0_0,
            id=request["job_id"],
            task_id=task["id"],
            kind=JobKind.EXPLOIT if kind is PocKind.EXPLOIT else JobKind.PROOF,
            tool=self._tool,
            arguments=cast(JsonObject, {"proof_request": dict(request)}),
            input_refs=[request["script_ref"]],
            status=JobStatus.QUEUED,
            idempotency_key=request["id"],
            resource_budget=request["resource_budget"],
            retry_policy=self._retry_policy,
            attempt=0,
            lease=None,
            failure=None,
            created_at=created_at,
            updated_at=created_at,
        )
        event = JobRequestedEvent(
            schema_version=SchemaVersion.VALUE_1_0_0,
            event_id=f"event:{job['id']}:requested",
            event_type="job.requested",
            aggregate_id=job["id"],
            sequence=0,
            occurred_at=created_at,
            correlation_id=task["id"],
            causation_id=request["id"],
            payload={
                "job_id": job["id"],
                "task_id": task["id"],
                "job_kind": job["kind"],
                "attempt": 0,
            },
        )
        return (await repositories.jobs.enqueue_with_outbox(job, event)).job
