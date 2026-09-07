from __future__ import annotations

from vulnweaver_contracts import (
    FindingStatus,
    JobKind,
    JobStatus,
    PocStatus,
    TaskResult,
    TaskStatus,
)
from vulnweaver_domain import JobSnapshot, aggregate_task


def test_empty_task_stays_created() -> None:
    aggregate = aggregate_task([], [], [])
    assert aggregate.status is TaskStatus.CREATED
    assert aggregate.result is None


def test_latest_active_phase_wins_without_becoming_a_lock() -> None:
    aggregate = aggregate_task(
        [
            JobSnapshot(JobKind.SOURCE_ANALYSIS, JobStatus.RUNNING),
            JobSnapshot(JobKind.REVIEW, JobStatus.QUEUED),
        ],
        [FindingStatus.CANDIDATE],
        [],
    )
    assert aggregate.status is TaskStatus.REVIEWING
    assert aggregate.result is None


def test_single_tool_failure_preserves_success_as_partial() -> None:
    aggregate = aggregate_task(
        [
            JobSnapshot(JobKind.SOURCE_ANALYSIS, JobStatus.SUCCEEDED),
            JobSnapshot(JobKind.BINARY_ANALYSIS, JobStatus.FAILED),
        ],
        [FindingStatus.CONFIRMED],
        [],
    )
    assert aggregate.status is TaskStatus.COMPLETED
    assert aggregate.result is TaskResult.PARTIAL


def test_all_failed_jobs_fail_the_task() -> None:
    aggregate = aggregate_task(
        [JobSnapshot(JobKind.VALIDATE, JobStatus.FAILED)],
        [],
        [],
    )
    assert aggregate.status is TaskStatus.FAILED
    assert aggregate.result is None


def test_success_without_findings_is_explicit() -> None:
    aggregate = aggregate_task(
        [JobSnapshot(JobKind.REPORT, JobStatus.SUCCEEDED)],
        [],
        [],
    )
    assert aggregate.status is TaskStatus.COMPLETED
    assert aggregate.result is TaskResult.NO_FINDINGS


def test_unfinished_poc_makes_completed_task_partial() -> None:
    aggregate = aggregate_task(
        [JobSnapshot(JobKind.REPORT, JobStatus.SUCCEEDED)],
        [FindingStatus.CONFIRMED],
        [PocStatus.FAILED],
    )
    assert aggregate.result is TaskResult.PARTIAL


def test_cancellation_request_has_priority() -> None:
    aggregate = aggregate_task(
        [JobSnapshot(JobKind.SOURCE_ANALYSIS, JobStatus.RUNNING)],
        [],
        [],
        cancellation_requested=True,
    )
    assert aggregate.status is TaskStatus.CANCELLED
