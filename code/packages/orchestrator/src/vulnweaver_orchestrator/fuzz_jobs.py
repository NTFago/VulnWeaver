"""Idempotent scheduling of fuzz jobs for findings."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from typing import cast

from vulnweaver_contracts import (
    CrashRecord,
    Evidence,
    EvidenceRelation,
    EvidenceStrength,
    EvidenceType,
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
from vulnweaver_fuzzing import build_fuzz_request
from vulnweaver_persistence import Database, Repositories


@dataclass(frozen=True, slots=True)
class FuzzTarget:
    """Everything the executor needs to build a fixed, sandbox-bound fuzz request."""

    artifact_version_id: str
    target_ref: str
    seed_refs: tuple[str, ...]
    image_digest: str
    max_executions: int
    max_duration_seconds: int
    max_crashes: int
    collect_coverage: bool = True


class FuzzJobScheduler:
    def __init__(self, database: Database, *, retry_policy: RetryPolicy | None = None) -> None:
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

    async def schedule(
        self, source_job: Job, targets: dict[str, FuzzTarget]
    ) -> tuple[str, ...]:
        """Enqueue one idempotent fuzz Job per Finding, with its fixed request bound."""
        async with self._database.transaction() as repositories:
            task = await repositories.tasks.get(source_job["task_id"], for_update=True)
            created: list[str] = []
            for finding_id in sorted(set(targets)):
                finding = await repositories.findings.get(finding_id)
                if finding["task_id"] != task["id"]:
                    raise ValueError("fuzz finding does not belong to source task")
                job_id = _id("job", "fuzz", finding_id)
                target = targets[finding_id]
                job = Job(
                    schema_version=SchemaVersion.VALUE_1_0_0,
                    id=job_id,
                    task_id=task["id"],
                    kind=JobKind.FUZZ,
                    # Bound below, once the fixed request exists for this Job id.
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
                # The executor only accepts a request already bound to this Job id,
                # so it is constructed from the identical Job identity.
                request = build_fuzz_request(
                    job,
                    artifact_version_id=target.artifact_version_id,
                    target_ref=target.target_ref,
                    seed_refs=list(target.seed_refs),
                    image_digest=target.image_digest,
                    max_executions=target.max_executions,
                    max_duration_seconds=target.max_duration_seconds,
                    max_crashes=target.max_crashes,
                    collect_coverage=target.collect_coverage,
                )
                job = cast(
                    Job,
                    {
                        **job,
                        "arguments": {
                            "finding_id": finding_id,
                            "fuzz_request": dict(request),
                        },
                    },
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
    repositories: Repositories,
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


async def persist_crash_evidence(
    repositories: Repositories,
    *,
    finding_id: str,
    crashes: Sequence[CrashRecord],
    created_by: str,
) -> tuple[str, ...]:
    """Persist minimized crash inputs as reproducible Finding evidence."""
    ordered = sorted(crashes, key=lambda item: item["id"])
    evidence_ids: list[str] = []
    for crash in ordered:
        evidence_id = _id("evidence", "fuzz-crash", crash["id"])
        await repositories.evidence.create(
            Evidence(
                schema_version=SchemaVersion.VALUE_1_0_0,
                id=evidence_id,
                type=EvidenceType.CRASH_RECORD,
                strength=EvidenceStrength.STRONG,
                artifact_ref=crash["input_ref"],
                digest=crash["input_digest"],
                tool=crash["tool"],
                input_ref=crash["input_ref"],
                command_hash=None,
                exit_code=crash["exit_code"],
                stdout_ref=None,
                stderr_ref=crash["stderr_ref"],
                replay_recipe=cast(
                    JsonObject,
                    {
                        "kind": "fuzz_crash",
                        "reproducible": True,
                        "crash_id": crash["id"],
                        "artifact_version_id": crash["artifact_version_id"],
                        "stack_hash": crash["stack_hash"],
                        "signal": crash["signal"],
                        "fuzz_tool": crash["fuzz_tool"],
                    },
                ),
                created_at=crash["created_at"],
            )
        )
        evidence_ids.append(evidence_id)
    return await link_fuzz_evidence(
        repositories,
        finding_id=finding_id,
        evidence_ids=evidence_ids,
        created_by=created_by,
        created_at=ordered[0]["created_at"] if ordered else "1970-01-01T00:00:00Z",
    )


def _id(*parts: str) -> str:
    return hashlib.sha256(":".join(parts).encode()).hexdigest()[:32]
