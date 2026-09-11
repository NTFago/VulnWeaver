"""Durable review Job scheduling and execution."""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Mapping, Sequence
from typing import Protocol, cast

from vulnweaver_contracts import (
    FailureKind,
    Job,
    JobKind,
    JobRequestedEvent,
    JobStatus,
    JsonObject,
    ResourceBudget,
    RetryPolicy,
    SchemaVersion,
    StructuredFailure,
    WorkerResult,
)
from vulnweaver_persistence import Database, EntityNotFound, Repositories

from vulnweaver_orchestrator.model_reviews import IndependentModelReviewer, ModelReviewResult


class ReviewModel(Protocol):
    async def review(
        self,
        finding_id: str,
        *,
        attempt_key: str,
        max_output_tokens: int | None = None,
    ) -> ModelReviewResult: ...


class ReviewJobScheduler:
    """Create exactly one queued review Job for each normalized Finding."""

    def __init__(
        self,
        database: Database,
        *,
        retry_policy: RetryPolicy | None = None,
    ) -> None:
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
            return await self.schedule_in_transaction(repositories, source_job, finding_ids)

    async def schedule_in_transaction(
        self,
        repositories: Repositories,
        source_job: Job,
        finding_ids: Sequence[str],
        *,
        revision: str | None = None,
    ) -> tuple[str, ...]:
        """Queue a review per finding.

        ``revision`` distinguishes a re-review from the finding's first review:
        the first one keeps the plain deterministic id (and stays idempotent),
        while a later revision — evidence that arrived after that review, such
        as a reproduced crash — gets its own id so it can actually run.
        """

        created: list[str] = []
        suffix = () if revision is None else (revision,)
        task = await repositories.tasks.get(source_job["task_id"], for_update=True)
        for finding_id in sorted(set(finding_ids)):
            finding = await repositories.findings.get(finding_id)
            if finding["task_id"] != task["id"]:
                raise ValueError("review finding does not belong to the source job task")
            job_id = _stable_identifier("job", "review", finding_id, *suffix)
            created_at = finding["created_at"]
            job = Job(
                schema_version=SchemaVersion.VALUE_1_0_0,
                id=job_id,
                task_id=task["id"],
                kind=JobKind.REVIEW,
                arguments=cast(JsonObject, {"finding_id": finding_id}),
                input_refs=source_job["input_refs"],
                status=JobStatus.QUEUED,
                idempotency_key=_stable_identifier("review", task["id"], finding_id, *suffix),
                resource_budget=cast(ResourceBudget, dict(task["resource_budget"])),
                retry_policy=self._retry_policy,
                attempt=0,
                lease=None,
                failure=None,
                created_at=created_at,
                updated_at=created_at,
            )
            event = JobRequestedEvent(
                schema_version=SchemaVersion.VALUE_1_0_0,
                event_id=_stable_identifier("event", job_id, "requested"),
                event_type="job.requested",
                aggregate_id=job_id,
                sequence=0,
                occurred_at=created_at,
                correlation_id=task["id"],
                causation_id=source_job["id"],
                payload={
                    "job_id": job_id,
                    "task_id": task["id"],
                    "job_kind": JobKind.REVIEW,
                    "attempt": 0,
                },
            )
            scheduled = await repositories.jobs.enqueue_with_outbox(job, event)
            if scheduled.created:
                created.append(job_id)
        return tuple(created)


class ReviewJobExecutor:
    def __init__(self, reviewer: ReviewModel | IndependentModelReviewer | None) -> None:
        self._reviewer = reviewer

    async def execute(self, job: Job, cancellation: asyncio.Event) -> WorkerResult:
        if job["kind"] is not JobKind.REVIEW:
            return _failed(job["id"], "review.invalid_job_kind", FailureKind.VALIDATION)
        if cancellation.is_set():
            return WorkerResult(
                schema_version=SchemaVersion.VALUE_1_0_0,
                job_id=job["id"],
                status=JobStatus.CANCELLED,
                produced_artifact_version_ids=[],
                evidence_ids=[],
                failure=None,
            )
        finding_id = _finding_id(job)
        if finding_id is None:
            return _failed(job["id"], "review.finding_id_required", FailureKind.VALIDATION)
        # max_model_tokens 0 means uncapped; compute-resource budgets no longer gate jobs.
        max_tokens = job["resource_budget"]["max_model_tokens"] or None
        if self._reviewer is None:
            return _failed(job["id"], "review.model_unconfigured", FailureKind.DEPENDENCY)
        try:
            outcome = await self._reviewer.review(
                finding_id,
                attempt_key=f"{job['id']}:attempt:{job['attempt']}",
                max_output_tokens=max_tokens,
            )
        except EntityNotFound:
            return _failed(job["id"], "review.finding_not_found", FailureKind.VALIDATION)
        failure = outcome.run["failure"]
        evidence_ids = [outcome.evidence_id] if outcome.evidence_id is not None else []
        if failure is not None:
            return WorkerResult(
                schema_version=SchemaVersion.VALUE_1_0_0,
                job_id=job["id"],
                status=JobStatus.FAILED,
                produced_artifact_version_ids=[],
                evidence_ids=evidence_ids,
                failure=failure,
            )
        return WorkerResult(
            schema_version=SchemaVersion.VALUE_1_0_0,
            job_id=job["id"],
            status=JobStatus.SUCCEEDED,
            produced_artifact_version_ids=[],
            evidence_ids=evidence_ids,
            failure=None,
        )


def _finding_id(job: Job) -> str | None:
    arguments = job.get("arguments")
    value = arguments.get("finding_id") if isinstance(arguments, Mapping) else None
    return value if isinstance(value, str) and value else None


def _failed(job_id: str, code: str, kind: FailureKind) -> WorkerResult:
    return WorkerResult(
        schema_version=SchemaVersion.VALUE_1_0_0,
        job_id=job_id,
        status=JobStatus.FAILED,
        produced_artifact_version_ids=[],
        evidence_ids=[],
        failure=StructuredFailure(
            code=code,
            kind=kind,
            message=code.replace(".", " "),
            retryable=False,
            details={},
        ),
    )


def _stable_identifier(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\0".join(parts).encode()).hexdigest()[:32]
    return f"{prefix}:{digest}"
