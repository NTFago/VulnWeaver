"""Durable scheduling for report generation jobs."""

from __future__ import annotations

from typing import cast

from vulnweaver_contracts import (
    FailureKind,
    Job,
    JobKind,
    JobRequestedEvent,
    JobStatus,
    JsonObject,
    RetryPolicy,
    SchemaVersion,
    ToolIdentity,
)
from vulnweaver_persistence import Repositories


class ReportJobScheduler:
    """Create one idempotent report Job and its Outbox event per Task."""

    def __init__(self, *, tool: ToolIdentity) -> None:
        self._tool = tool
        self._retry_policy = RetryPolicy(
            max_attempts=2,
            backoff_seconds=5.0,
            retryable_failure_kinds=[FailureKind.TIMEOUT, FailureKind.ENVIRONMENT],
        )

    async def schedule(
        self,
        repositories: Repositories,
        task_id: str,
        *,
        artifact_id: str,
        version_id: str,
        parent_version_id: str,
        report_format: str = "markdown",
    ) -> Job:
        if report_format not in {"markdown", "sarif", "pdf"}:
            raise ValueError("unsupported report format")
        task = await repositories.tasks.get(task_id, for_update=True)
        created_at = task["updated_at"]
        job_id = f"job:report:{task_id}:{report_format}"
        job = Job(
            schema_version=SchemaVersion.VALUE_1_0_0,
            id=job_id,
            task_id=task_id,
            kind=JobKind.REPORT,
            tool=self._tool,
            arguments=cast(
                JsonObject,
                {
                    "task_id": task_id,
                    "artifact_id": artifact_id,
                    "version_id": version_id,
                    "parent_version_id": parent_version_id,
                    "format": report_format,
                },
            ),
            input_refs=[],
            status=JobStatus.QUEUED,
            idempotency_key=f"report:{task_id}:{report_format}",
            resource_budget=task["resource_budget"],
            retry_policy=self._retry_policy,
            attempt=0,
            lease=None,
            failure=None,
            created_at=created_at,
            updated_at=created_at,
        )
        event = JobRequestedEvent(
            schema_version=SchemaVersion.VALUE_1_0_0,
            event_id=f"event:{job_id}:requested",
            event_type="job.requested",
            aggregate_id=job_id,
            sequence=0,
            occurred_at=created_at,
            correlation_id=task_id,
            causation_id=None,
            payload={
                "job_id": job_id,
                "task_id": task_id,
                "job_kind": JobKind.REPORT,
                "attempt": 0,
            },
        )
        return (await repositories.jobs.enqueue_with_outbox(job, event)).job
