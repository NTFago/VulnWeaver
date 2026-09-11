"""Project Task state from durable child facts during Job settlement."""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Sequence
from typing import Protocol

from vulnweaver_contracts import (
    FindingStatus,
    Job,
    JobKind,
    JobStatus,
    SchemaVersion,
    StructuredFailure,
    TaskResult,
    TaskStatus,
    TaskStatusChangedEvent,
    WorkerResult,
)
from vulnweaver_domain import JobSnapshot, aggregate_task, transition_task
from vulnweaver_domain.transitions import TASK_TRANSITIONS
from vulnweaver_persistence import Repositories

from vulnweaver_orchestrator.audit_plan import AuditPlan, build_baseline_plan, complete_baselines
from vulnweaver_orchestrator.review_jobs import ReviewJobScheduler
from vulnweaver_orchestrator.semantic_audit import SemanticAuditScheduler

LOGGER = logging.getLogger("vulnweaver.orchestrator.aggregation")

_AUDIT_BASELINES = ("static_rules", "semantic_function_audit")

_PHASES = (
    TaskStatus.CREATED,
    TaskStatus.VALIDATING,
    TaskStatus.ANALYZING,
    TaskStatus.REVIEWING,
    TaskStatus.VERIFYING,
    TaskStatus.EXPLOITING,
    TaskStatus.REPORTING,
    TaskStatus.COMPLETED,
)
_TERMINAL = frozenset({TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED})
_JOB_PHASES = {
    JobKind.VALIDATE: TaskStatus.VALIDATING,
    JobKind.IMPORT: TaskStatus.VALIDATING,
    JobKind.SOURCE_ANALYSIS: TaskStatus.ANALYZING,
    JobKind.SEMANTIC_AUDIT: TaskStatus.ANALYZING,
    JobKind.BINARY_ANALYSIS: TaskStatus.ANALYZING,
    JobKind.REVIEW: TaskStatus.REVIEWING,
    JobKind.FUZZ: TaskStatus.VERIFYING,
    JobKind.PROOF: TaskStatus.VERIFYING,
    JobKind.EXPLOIT: TaskStatus.EXPLOITING,
    JobKind.REPORT: TaskStatus.REPORTING,
}
_ACTIVE = frozenset(
    {JobStatus.PENDING, JobStatus.QUEUED, JobStatus.RUNNING, JobStatus.WAITING_PERMISSION}
)


class ExploitDispatchScheduler(Protocol):
    """Implemented by the proof package; dispatches auto-exploit Jobs."""

    async def schedule_in_transaction(
        self, repositories: Repositories, finding_id: str
    ) -> str | None: ...


class FuzzDispatchScheduler(Protocol):
    """Implemented by the orchestrator fuzz scheduler; enqueues one fuzz Job."""

    async def schedule_finding_in_transaction(
        self, repositories: Repositories, finding_id: str
    ) -> str | None: ...


class ReportDispatchScheduler(Protocol):
    async def schedule_default(
        self,
        repositories: Repositories,
        task_id: str,
        parent_version_id: str,
        *,
        causation_id: str | None = None,
    ) -> Job: ...


class TaskAggregateSettlementHook:
    def __init__(
        self,
        review_scheduler: ReviewJobScheduler | None = None,
        audit_scheduler: SemanticAuditScheduler | None = None,
        exploit_scheduler: ExploitDispatchScheduler | None = None,
        fuzz_scheduler: FuzzDispatchScheduler | None = None,
        report_scheduler: ReportDispatchScheduler | None = None,
    ) -> None:
        self._review_scheduler = review_scheduler
        self._audit_scheduler = audit_scheduler
        self._exploit_scheduler = exploit_scheduler
        self._fuzz_scheduler = fuzz_scheduler
        self._report_scheduler = report_scheduler

    async def after_terminal(
        self, repositories: Repositories, job: Job, result: WorkerResult
    ) -> None:
        task = await repositories.tasks.get(job["task_id"], for_update=True)
        if task["status"] in _TERMINAL:
            return
        jobs = await repositories.jobs.list_for_task(task["id"])
        findings = await repositories.findings.list_for_task(task["id"])
        if (
            self._audit_scheduler is not None
            and (
                job["kind"] is JobKind.SOURCE_ANALYSIS
                or job["kind"] is JobKind.IMPORT
            )
            and not any(
                item["kind"] is JobKind.SOURCE_ANALYSIS and item["status"] in _ACTIVE
                for item in jobs
            )
            and not any(item["kind"] is JobKind.SEMANTIC_AUDIT for item in jobs)
        ):
            # ADR-021: the semantic baseline runs after the static baseline and
            # before review so model-discovered candidates are also reviewed.
            await self._audit_scheduler.schedule_in_transaction(repositories, job)
            jobs = await repositories.jobs.list_for_task(task["id"])
        analysis_pending = any(
            item["kind"] in {JobKind.SOURCE_ANALYSIS, JobKind.SEMANTIC_AUDIT}
            and item["status"] in _ACTIVE
            for item in jobs
        )
        if (
            self._review_scheduler is not None
            and job["kind"] in {JobKind.SOURCE_ANALYSIS, JobKind.SEMANTIC_AUDIT}
            and not analysis_pending
        ):
            await self._review_scheduler.schedule_in_transaction(
                repositories,
                job,
                [finding["id"] for finding in findings],
            )
            jobs = await repositories.jobs.list_for_task(task["id"])
        review_pending = any(
            item["kind"] is JobKind.REVIEW and item["status"] in _ACTIVE for item in jobs
        )
        if (
            self._exploit_scheduler is not None
            and job["kind"] is JobKind.REVIEW
            and not review_pending
        ):
            # T31: confirmed findings flow into automatic exploit verification
            # when the project opted in; the scheduler enforces the gates again.
            project = await repositories.projects.get(task["project_id"])
            if project["exploit_validation_enabled"]:
                for finding in findings:
                    if finding["status"] is FindingStatus.CONFIRMED:
                        await self._exploit_scheduler.schedule_in_transaction(
                            repositories, finding["id"]
                        )
        if (
            self._fuzz_scheduler is not None
            and job["kind"] is JobKind.REVIEW
            and not review_pending
        ):
            # T32: fuzzing is dynamic execution, so it uses the same explicit
            # project opt-in as exploit verification. The scheduler resolves the
            # target and seeds and declines when it has no bounded target to run.
            project = await repositories.projects.get(task["project_id"])
            if project["exploit_validation_enabled"]:
                for finding in findings:
                    if finding["status"] is not FindingStatus.FALSE_POSITIVE:
                        await self._fuzz_scheduler.schedule_finding_in_transaction(
                            repositories, finding["id"]
                        )
        if (
            self._review_scheduler is not None
            and job["kind"] in {JobKind.FUZZ, JobKind.PROOF}
            and result["evidence_ids"]
            and not review_pending
        ):
            # Dynamic verification lands its evidence *after* the finding's first
            # review, and a settled fuzz/proof Job otherwise never re-opens
            # review — so a reproduced crash could never reach the confirmation
            # gate. Re-review only the findings that job actually attached
            # evidence to, under a revision id so the first review keeps its own.
            touched = set(result["evidence_ids"])
            for finding in findings:
                relations = await repositories.findings.list_evidence_relations(finding["id"])
                linked = sorted(
                    relation["evidence_id"]
                    for relation in relations
                    if relation["evidence_id"] in touched
                )
                if not linked:
                    continue
                revision = "evidence-" + hashlib.sha256(
                    "\0".join(linked).encode()
                ).hexdigest()[:16]
                await self._review_scheduler.schedule_in_transaction(
                    repositories, job, [finding["id"]], revision=revision
                )
            jobs = await repositories.jobs.list_for_task(task["id"])
        # Dynamic schedulers run in this transaction. Reload their durable Jobs
        # before aggregation so a newly queued proof/fuzz Job cannot be skipped.
        jobs = await repositories.jobs.list_for_task(task["id"])
        non_report_pending = any(
            item["kind"] is not JobKind.REPORT and item["status"] in _ACTIVE for item in jobs
        )
        if (
            self._report_scheduler is not None
            and not non_report_pending
            and not any(
                item["id"] == f"job:report:{task['id']}:markdown" for item in jobs
            )
            and task["artifact_version_ids"]
            and _has_reportable_result(jobs)
        ):
            await self._report_scheduler.schedule_default(
                repositories,
                task["id"],
                task["artifact_version_ids"][0],
                causation_id=job["id"],
            )
            jobs = await repositories.jobs.list_for_task(task["id"])
        aggregate = aggregate_task(
            [JobSnapshot(kind=item["kind"], status=item["status"]) for item in jobs],
            [item["status"] for item in findings],
            [],
        )
        transitions = _transition_path(task["status"], aggregate.status, aggregate.result, jobs)
        if aggregate.result is TaskResult.NO_FINDINGS and self._audit_scheduler is not None:
            plan = _audit_plan(jobs)
            if plan.missing_required():
                # ADR-021: NO_FINDINGS requires the required audit baselines to
                # have actually run; blocking beats silently reporting a clean
                # scan when the semantic baseline never completed.
                LOGGER.warning(
                    "audit_plan_no_findings_blocked",
                    extra={
                        "task_id": task["id"],
                        "job_id": job["id"],
                        "missing_required": list(plan.missing_required()),
                        "coverage": plan.coverage(),
                    },
                )
                transitions = [
                    (status, task_result)
                    for status, task_result in transitions
                    if status is not TaskStatus.COMPLETED
                ]
        for status, task_result in transitions:
            allowed_now = TASK_TRANSITIONS.get(task["status"], frozenset())
            if status not in allowed_now:
                LOGGER.warning(
                    "task_aggregation_transition_skipped",
                    extra={
                        "task_id": task["id"],
                        "job_id": job["id"],
                        "current_status": str(task["status"]),
                        "target_status": str(status),
                    },
                )
                continue
            transition_task(task["status"], status)
            # A task that ends as FAILED must say which job failed and why, otherwise the API
            # and UI can only report that something went wrong.
            task_failure = _task_failure(jobs) if status is TaskStatus.FAILED else None
            updated = await repositories.tasks.set_status(
                task["id"], status, result=task_result, failure=task_failure
            )
            if not updated.changed:
                task = updated.task
                continue
            sequence = await repositories.task_events.next_sequence(task["id"])
            event = _status_event(
                task_id=task["id"],
                previous=updated.previous_status,
                current=status,
                result=task_result,
                sequence=sequence,
                occurred_at=updated.task["updated_at"],
                causation_id=job["id"],
                failure=task_failure,
            )
            await repositories.task_events.append(event)
            await repositories.outbox.add(event)
            task = updated.task


def _audit_plan(jobs: list[Job]) -> AuditPlan:
    """Derive the durable audit-plan completion from settled Job facts."""
    required = (
        ("semantic_function_audit",)
        if any(_is_binary_import(item) for item in jobs)
        else _AUDIT_BASELINES
    )
    plan = build_baseline_plan(*required)
    completed: list[str] = []
    if any(
        item["kind"] is JobKind.SOURCE_ANALYSIS and item["status"] is JobStatus.SUCCEEDED
        for item in jobs
    ):
        completed.append("static_rules")
    elif any(
        item["kind"] is JobKind.IMPORT
        and not _is_binary_import(item)
        and item["status"] is JobStatus.SUCCEEDED
        for item in jobs
    ) and not any(item["kind"] is JobKind.SOURCE_ANALYSIS for item in jobs):
        # A source import with no applicable scanner Jobs records the static
        # baseline as not applicable; semantic audit remains mandatory.
        completed.append("static_rules")
    if any(
        item["kind"] is JobKind.SEMANTIC_AUDIT and item["status"] is JobStatus.SUCCEEDED
        for item in jobs
    ):
        completed.append("semantic_function_audit")
    return complete_baselines(plan, completed)


def _is_binary_import(job: Job) -> bool:
    tool = job.get("tool")
    return (
        job["kind"] is JobKind.IMPORT
        and isinstance(tool, dict)
        and tool.get("name") == "binary-import"
    )


def _has_reportable_result(jobs: list[Job]) -> bool:
    return any(
        item["status"] is JobStatus.SUCCEEDED
        and item["kind"]
        in {
            JobKind.IMPORT,
            JobKind.SOURCE_ANALYSIS,
            JobKind.SEMANTIC_AUDIT,
            JobKind.BINARY_ANALYSIS,
            JobKind.REVIEW,
            JobKind.FUZZ,
            JobKind.PROOF,
            JobKind.EXPLOIT,
        }
        for item in jobs
    )


def _transition_path(
    current: TaskStatus,
    target: TaskStatus,
    result: TaskResult | None,
    jobs: list[Job],
) -> list[tuple[TaskStatus, TaskResult | None]]:
    if current is target:
        return []
    if target in {TaskStatus.FAILED, TaskStatus.CANCELLED}:
        return [(target, None)]
    phases = {_JOB_PHASES[item["kind"]] for item in jobs}
    # A scanner can only be scheduled after source/binary input validation.  This
    # keeps historical phase events coherent even when the first aggregation runs
    # after the import Job has already settled.
    if phases - {TaskStatus.VALIDATING}:
        phases.add(TaskStatus.VALIDATING)
    if target is TaskStatus.COMPLETED:
        phases.add(TaskStatus.COMPLETED)
    elif target not in phases:
        return []
    current_index = _PHASES.index(current)
    selected: list[TaskStatus] = []
    previous = current
    for phase in _PHASES[current_index + 1 :]:
        # Out-of-order settlement can ask for a phase whose predecessors never
        # ran (e.g. a proof job on a task still validating).  Illegal hops are
        # skipped so the aggregate degrades instead of poisoning the Job.
        allowed = TASK_TRANSITIONS.get(previous, frozenset())
        if phase not in phases or phase not in allowed:
            continue
        selected.append(phase)
        previous = phase
    return [(item, result if item is TaskStatus.COMPLETED else None) for item in selected]


def _task_failure(jobs: Sequence[Job]) -> StructuredFailure | None:
    """Return the earliest job failure as the task-level reason, tagged with its job."""

    for item in jobs:
        failure = item["failure"]
        if item["status"] is not JobStatus.FAILED or failure is None:
            continue
        return StructuredFailure(
            code=failure["code"],
            kind=failure["kind"],
            message=failure["message"],
            retryable=failure["retryable"],
            details={**failure["details"], "job_id": item["id"], "job_kind": str(item["kind"])},
        )
    return None


def _status_event(
    *,
    task_id: str,
    previous: TaskStatus,
    current: TaskStatus,
    result: TaskResult | None,
    sequence: int,
    occurred_at: str,
    causation_id: str,
    failure: StructuredFailure | None = None,
) -> TaskStatusChangedEvent:
    event_id = (
        "event:" + hashlib.sha256(f"{task_id}\0{sequence}\0{current}".encode()).hexdigest()[:32]
    )
    return TaskStatusChangedEvent(
        schema_version=SchemaVersion.VALUE_1_0_0,
        event_id=event_id,
        event_type="task.status_changed",
        aggregate_id=task_id,
        sequence=sequence,
        occurred_at=occurred_at,
        correlation_id=task_id,
        causation_id=causation_id,
        payload={
            "task_id": task_id,
            "previous_status": previous,
            "status": current,
            "result": result,
            "failure": failure,
        },
    )
