"""Project Task state from durable child facts during Job settlement."""

from __future__ import annotations

import hashlib

from vulnweaver_contracts import (
    Job,
    JobKind,
    JobStatus,
    SchemaVersion,
    TaskResult,
    TaskStatus,
    TaskStatusChangedEvent,
    WorkerResult,
)
from vulnweaver_domain import JobSnapshot, aggregate_task, transition_task
from vulnweaver_persistence import Repositories

from vulnweaver_orchestrator.review_jobs import ReviewJobScheduler

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


class TaskAggregateSettlementHook:
    def __init__(self, review_scheduler: ReviewJobScheduler | None = None) -> None:
        self._review_scheduler = review_scheduler

    async def after_terminal(
        self, repositories: Repositories, job: Job, result: WorkerResult
    ) -> None:
        task = await repositories.tasks.get(job["task_id"], for_update=True)
        if task["status"] in _TERMINAL:
            return
        jobs = await repositories.jobs.list_for_task(task["id"])
        findings = await repositories.findings.list_for_task(task["id"])
        if (
            self._review_scheduler is not None
            and job["kind"] is JobKind.SOURCE_ANALYSIS
            and not any(
                item["kind"] is JobKind.SOURCE_ANALYSIS
                and item["status"]
                in {
                    JobStatus.PENDING,
                    JobStatus.QUEUED,
                    JobStatus.RUNNING,
                    JobStatus.WAITING_PERMISSION,
                }
                for item in jobs
            )
        ):
            await self._review_scheduler.schedule_in_transaction(
                repositories,
                job,
                [finding["id"] for finding in findings],
            )
            jobs = await repositories.jobs.list_for_task(task["id"])
        aggregate = aggregate_task(
            [JobSnapshot(kind=item["kind"], status=item["status"]) for item in jobs],
            [item["status"] for item in findings],
            [],
        )
        for status, task_result in _transition_path(
            task["status"], aggregate.status, aggregate.result
        ):
            transition_task(task["status"], status)
            updated = await repositories.tasks.set_status(
                task["id"], status, result=task_result
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
            )
            await repositories.task_events.append(event)
            await repositories.outbox.add(event)
            task = updated.task


def _transition_path(
    current: TaskStatus, target: TaskStatus, result: TaskResult | None
) -> list[tuple[TaskStatus, TaskResult | None]]:
    if current is target:
        return []
    if target in {TaskStatus.FAILED, TaskStatus.CANCELLED}:
        return [(target, None)]
    current_index = _PHASES.index(current)
    target_index = _PHASES.index(target)
    if target_index <= current_index:
        return []
    selected = list(_PHASES[current_index + 1 : target_index + 1])
    if target is TaskStatus.COMPLETED:
        selected = [
            item
            for item in selected
            if item not in {TaskStatus.VERIFYING, TaskStatus.EXPLOITING}
        ]
    return [(item, result if item is TaskStatus.COMPLETED else None) for item in selected]


def _status_event(
    *,
    task_id: str,
    previous: TaskStatus,
    current: TaskStatus,
    result: TaskResult | None,
    sequence: int,
    occurred_at: str,
    causation_id: str,
) -> TaskStatusChangedEvent:
    event_id = "event:" + hashlib.sha256(
        f"{task_id}\0{sequence}\0{current}".encode()
    ).hexdigest()[:32]
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
        },
    )
