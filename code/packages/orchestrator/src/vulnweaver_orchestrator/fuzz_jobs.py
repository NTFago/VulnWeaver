"""Idempotent scheduling of fuzz jobs for findings."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from typing import Protocol, cast

from vulnweaver_contracts import (
    EvidenceRelation,
    FailureKind,
    FindingEvidence,
    Job,
    JobKind,
    JobRequestedEvent,
    JobStatus,
    JsonObject,
    ResourceBudget,
    RetryPolicy,
    SchemaVersion,
)


class FuzzRepositories(Protocol):
    tasks: object
    findings: object
    jobs: object


class FuzzJobScheduler:
    def __init__(self, database: object, *, retry_policy: RetryPolicy | None = None) -> None:
        self._database = database
        self._retry_policy = retry_policy or RetryPolicy(
            max_attempts=2,
            backoff_seconds=5.0,
            retryable_failure_kinds=[
                FailureKind.TIMEOUT,
                FailureKind.ENVIRONMENT,
                FailureKind.DEPENDENCY,
            ],
        )

    async def schedule(self, source_job: Job, finding_ids: Sequence[str]) -> tuple[str, ...]:
        async with self._database.transaction() as repositories:
            task = await repositories.tasks.get(source_job["task_id"], for_update=True)
            created: list[str] = []
            for finding_id in sorted(set(finding_ids)):
                finding = await repositories.findings.get(finding_id)
                if finding["task_id"] != task["id"]:
                    raise ValueError("fuzz finding does not belong to source task")
                job_id = _id("job", "fuzz", finding_id)
                job = Job(
                    schema_version=SchemaVersion.VALUE_1_0_0,
                    id=job_id,
                    task_id=task["id"],
                    kind=JobKind.FUZZ,
                    arguments=cast(JsonObject, {"finding_id": finding_id}),
                    input_refs=source_job["input_refs"],
                    status=JobStatus.QUEUED,
                    idempotency_key=_id("fuzz", task["id"], finding_id),
                    resource_budget=cast(ResourceBudget, dict(task["resource_budget"])),
                    retry_policy=self._retry_policy,
                    attempt=0,
                    lease=None,
                    failure=None,
                    created_at=task["created_at"],
                    updated_at=task["updated_at"],
                )
                event = JobRequestedEvent(
                    schema_version=SchemaVersion.VALUE_1_0_0,
                    event_id=_id("event", job_id),
                    event_type="job.requested",
                    aggregate_id=job_id,
                    sequence=0,
                    occurred_at=task["updated_at"],
                    correlation_id=task["id"],
                    causation_id=source_job["id"],
                    payload={
                        "job_id": job_id,
                        "task_id": task["id"],
                        "job_kind": JobKind.FUZZ,
                        "attempt": 0,
                    },
                )
                result = await repositories.jobs.enqueue_with_outbox(job, event)
                if result.created:
                    created.append(job_id)
            return tuple(created)


async def link_fuzz_evidence(
    repositories: FuzzRepositories,
    *,
    finding_id: str,
    evidence_ids: Sequence[str],
    created_by: str,
    created_at: str,
    weight: float = 1.0,
) -> tuple[str, ...]:
    """Attach crash-cluster evidence to a Finding without overwriting history."""
    if not 0.0 <= weight <= 1.0:
        raise ValueError("evidence weight must be between 0 and 1")
    linked: list[str] = []
    for evidence_id in sorted(set(evidence_ids)):
        relation = FindingEvidence(
            schema_version=SchemaVersion.VALUE_1_0_0,
            finding_id=finding_id,
            evidence_id=evidence_id,
            relation=EvidenceRelation.SUPPORTS,
            weight=weight,
            created_by=created_by,
            created_at=created_at,
        )
        await repositories.findings.link_evidence(relation)
        linked.append(evidence_id)
    return tuple(linked)


def _id(*parts: str) -> str:
    return hashlib.sha256(":".join(parts).encode()).hexdigest()[:32]
