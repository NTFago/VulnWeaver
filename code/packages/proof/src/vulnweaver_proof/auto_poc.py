"""Durable dispatch of candidate-stage PoC verification Jobs.

The scheduler runs inside the settlement hook after audit/review and enqueues
one PROOF Job per CANDIDATE finding when the project enables dynamic
verification. Candidate-stage execution is *reproduction*, not exploitation:
the script must show the suspected fault is real and nothing more, and the
confirmed-only gate for exploit Jobs (red line 10) is unchanged. Each finding
is scheduled at most once for its lifetime via a deterministic idempotency key.
"""

from __future__ import annotations

from typing import cast

from vulnweaver_contracts import (
    FailureKind,
    FindingStatus,
    Job,
    JobKind,
    JobRequestedEvent,
    JobStatus,
    JsonObject,
    ResourceBudget,
    RetryPolicy,
    SchemaVersion,
)
from vulnweaver_persistence import Database, Repositories

from .auto_exploit import POC_VERIFICATION_BASELINE, stable_id

POC_VERIFICATION = POC_VERIFICATION_BASELINE


class PocVerificationScheduler:
    """Enqueue one candidate-stage PoC verification Job per finding, idempotently."""

    def __init__(
        self,
        database: Database,
        *,
        image_digest: str,
        retry_policy: RetryPolicy | None = None,
    ) -> None:
        if not image_digest.startswith("sha256:") or len(image_digest) != 71:
            raise ValueError("poc verification scheduler requires a sha256 image digest")
        self._database = database
        self._image_digest = image_digest
        self._retry_policy = retry_policy or RetryPolicy(
            max_attempts=2,
            backoff_seconds=5.0,
            retryable_failure_kinds=[FailureKind.TIMEOUT, FailureKind.ENVIRONMENT],
        )

    async def schedule_in_transaction(
        self, repositories: Repositories, finding_id: str
    ) -> str | None:
        finding = await repositories.findings.get(finding_id)
        if finding["status"] is not FindingStatus.CANDIDATE:
            return None
        task = await repositories.tasks.get(finding["task_id"], for_update=True)
        project = await repositories.projects.get(task["project_id"])
        if not project["exploit_validation_enabled"]:
            return None
        job_id = stable_id("job", POC_VERIFICATION, finding["id"])
        created_at = task["updated_at"]
        job = Job(
            schema_version=SchemaVersion.VALUE_1_0_0,
            id=job_id,
            task_id=task["id"],
            kind=JobKind.PROOF,
            arguments=cast(
                JsonObject,
                {
                    POC_VERIFICATION: {
                        "finding_id": finding["id"],
                        "image_digest": self._image_digest,
                    }
                },
            ),
            input_refs=[finding["location"]["artifact_version_id"]],
            status=JobStatus.QUEUED,
            idempotency_key=stable_id(POC_VERIFICATION, finding["id"]),
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
            event_id=stable_id("event", job_id, "requested"),
            event_type="job.requested",
            aggregate_id=job_id,
            sequence=0,
            occurred_at=created_at,
            correlation_id=task["id"],
            causation_id=finding["id"],
            payload={
                "job_id": job_id,
                "task_id": task["id"],
                "job_kind": JobKind.PROOF,
                "attempt": 0,
            },
        )
        scheduled = await repositories.jobs.enqueue_with_outbox(job, event)
        return job["id"] if scheduled.created else None


__all__ = ["POC_VERIFICATION", "PocVerificationScheduler"]
