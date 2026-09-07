"""Task status/result aggregation from child facts."""

from __future__ import annotations

from dataclasses import dataclass

from vulnweaver_contracts import (
    FindingStatus,
    JobKind,
    JobStatus,
    PocStatus,
    TaskResult,
    TaskStatus,
)


@dataclass(frozen=True, slots=True)
class JobSnapshot:
    kind: JobKind
    status: JobStatus


@dataclass(frozen=True, slots=True)
class TaskAggregate:
    status: TaskStatus
    result: TaskResult | None


_ACTIVE_JOB_PHASE = {
    JobKind.VALIDATE: TaskStatus.VALIDATING,
    JobKind.IMPORT: TaskStatus.VALIDATING,
    JobKind.SOURCE_ANALYSIS: TaskStatus.ANALYZING,
    JobKind.BINARY_ANALYSIS: TaskStatus.ANALYZING,
    JobKind.REVIEW: TaskStatus.REVIEWING,
    JobKind.PROOF: TaskStatus.VERIFYING,
    JobKind.EXPLOIT: TaskStatus.EXPLOITING,
    JobKind.REPORT: TaskStatus.REPORTING,
}
_PHASE_PRIORITY = {
    TaskStatus.VALIDATING: 1,
    TaskStatus.ANALYZING: 2,
    TaskStatus.REVIEWING: 3,
    TaskStatus.VERIFYING: 4,
    TaskStatus.EXPLOITING: 5,
    TaskStatus.REPORTING: 6,
}
_ACTIVE_JOB_STATES = frozenset(
    {
        JobStatus.PENDING,
        JobStatus.QUEUED,
        JobStatus.RUNNING,
        JobStatus.WAITING_PERMISSION,
    }
)


def aggregate_task(
    jobs: list[JobSnapshot],
    finding_statuses: list[FindingStatus],
    poc_statuses: list[PocStatus],
    *,
    cancellation_requested: bool = False,
) -> TaskAggregate:
    """Derive Task state without using the Task row as an execution lock."""

    if cancellation_requested:
        return TaskAggregate(TaskStatus.CANCELLED, None)
    if not jobs:
        return TaskAggregate(TaskStatus.CREATED, None)

    active_jobs = [job for job in jobs if job.status in _ACTIVE_JOB_STATES]
    if active_jobs:
        phase = max(
            (_ACTIVE_JOB_PHASE[job.kind] for job in active_jobs),
            key=_PHASE_PRIORITY.__getitem__,
        )
        return TaskAggregate(phase, None)

    succeeded = sum(job.status is JobStatus.SUCCEEDED for job in jobs)
    failed_or_cancelled = sum(job.status in {JobStatus.FAILED, JobStatus.CANCELLED} for job in jobs)
    if succeeded == 0 and failed_or_cancelled:
        return TaskAggregate(TaskStatus.FAILED, None)

    incomplete_evidence = any(
        status in {FindingStatus.DISPUTED, FindingStatus.UNVERIFIABLE}
        for status in finding_statuses
    )
    incomplete_poc = any(status is not PocStatus.COMPLETED for status in poc_statuses)
    if failed_or_cancelled or incomplete_evidence or incomplete_poc:
        result = TaskResult.PARTIAL
    elif not finding_statuses:
        result = TaskResult.NO_FINDINGS
    else:
        result = TaskResult.SUCCESS
    return TaskAggregate(TaskStatus.COMPLETED, result)
