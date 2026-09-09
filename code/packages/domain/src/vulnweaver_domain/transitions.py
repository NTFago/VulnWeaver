"""Pure state-transition rules for persisted aggregates."""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum

from vulnweaver_contracts import FindingStatus, JobStatus, PocStatus, RunStatus, TaskStatus

from vulnweaver_domain.policies import ConfirmationDecision


class IllegalTransitionError(ValueError):
    def __init__(self, aggregate: str, current: StrEnum, target: StrEnum) -> None:
        self.aggregate = aggregate
        self.current = current
        self.target = target
        super().__init__(aggregate, current, target)

    def __str__(self) -> str:
        return f"illegal {self.aggregate} transition: {self.current.value} -> {self.target.value}"


class FindingConfirmationError(ValueError):
    def __init__(self, reason_codes: tuple[str, ...]) -> None:
        self.reason_codes = reason_codes
        super().__init__(*reason_codes)

    def __str__(self) -> str:
        reasons = ", ".join(self.reason_codes)
        return f"finding confirmation denied: {reasons}"


TASK_TRANSITIONS: Mapping[TaskStatus, frozenset[TaskStatus]] = {
    TaskStatus.CREATED: frozenset({TaskStatus.VALIDATING, TaskStatus.CANCELLED, TaskStatus.FAILED}),
    TaskStatus.VALIDATING: frozenset(
        {
            TaskStatus.ANALYZING,
            TaskStatus.COMPLETED,
            TaskStatus.CANCELLED,
            TaskStatus.FAILED,
        }
    ),
    TaskStatus.ANALYZING: frozenset(
        {
            TaskStatus.REVIEWING,
            TaskStatus.COMPLETED,
            TaskStatus.CANCELLED,
            TaskStatus.FAILED,
        }
    ),
    TaskStatus.REVIEWING: frozenset(
        {
            TaskStatus.VERIFYING,
            TaskStatus.EXPLOITING,
            TaskStatus.REPORTING,
            TaskStatus.COMPLETED,
            TaskStatus.CANCELLED,
            TaskStatus.FAILED,
        }
    ),
    TaskStatus.VERIFYING: frozenset(
        {
            TaskStatus.EXPLOITING,
            TaskStatus.REPORTING,
            TaskStatus.COMPLETED,
            TaskStatus.CANCELLED,
            TaskStatus.FAILED,
        }
    ),
    TaskStatus.EXPLOITING: frozenset(
        {
            TaskStatus.REPORTING,
            TaskStatus.COMPLETED,
            TaskStatus.CANCELLED,
            TaskStatus.FAILED,
        }
    ),
    TaskStatus.REPORTING: frozenset(
        {TaskStatus.COMPLETED, TaskStatus.CANCELLED, TaskStatus.FAILED}
    ),
    TaskStatus.COMPLETED: frozenset(),
    TaskStatus.FAILED: frozenset(),
    TaskStatus.CANCELLED: frozenset(),
}

JOB_TRANSITIONS: Mapping[JobStatus, frozenset[JobStatus]] = {
    JobStatus.PENDING: frozenset({JobStatus.QUEUED, JobStatus.CANCELLED}),
    JobStatus.QUEUED: frozenset({JobStatus.RUNNING, JobStatus.CANCELLED}),
    JobStatus.RUNNING: frozenset(
        {
            JobStatus.WAITING_PERMISSION,
            JobStatus.SUCCEEDED,
            JobStatus.FAILED,
            JobStatus.CANCELLED,
        }
    ),
    JobStatus.WAITING_PERMISSION: frozenset(
        {JobStatus.QUEUED, JobStatus.RUNNING, JobStatus.FAILED, JobStatus.CANCELLED}
    ),
    JobStatus.SUCCEEDED: frozenset(),
    JobStatus.FAILED: frozenset({JobStatus.QUEUED}),
    JobStatus.CANCELLED: frozenset(),
}

RUN_TRANSITIONS: Mapping[RunStatus, frozenset[RunStatus]] = {
    RunStatus.CREATED: frozenset({RunStatus.RUNNING, RunStatus.CANCELLED}),
    RunStatus.RUNNING: frozenset({RunStatus.SUCCEEDED, RunStatus.FAILED, RunStatus.CANCELLED}),
    RunStatus.SUCCEEDED: frozenset(),
    RunStatus.FAILED: frozenset(),
    RunStatus.CANCELLED: frozenset(),
}

POC_TRANSITIONS: Mapping[PocStatus, frozenset[PocStatus]] = {
    PocStatus.CREATED: frozenset({PocStatus.QUEUED, PocStatus.CANCELLED}),
    PocStatus.QUEUED: frozenset({PocStatus.RUNNING, PocStatus.CANCELLED}),
    PocStatus.RUNNING: frozenset({PocStatus.COMPLETED, PocStatus.FAILED, PocStatus.CANCELLED}),
    PocStatus.COMPLETED: frozenset(),
    PocStatus.FAILED: frozenset({PocStatus.QUEUED}),
    PocStatus.CANCELLED: frozenset(),
}

FINDING_TRANSITIONS: Mapping[FindingStatus, frozenset[FindingStatus]] = {
    FindingStatus.CANDIDATE: frozenset(
        {
            FindingStatus.CONFIRMED,
            FindingStatus.FALSE_POSITIVE,
            FindingStatus.DISPUTED,
            FindingStatus.UNVERIFIABLE,
        }
    ),
    FindingStatus.CONFIRMED: frozenset({FindingStatus.DISPUTED}),
    FindingStatus.FALSE_POSITIVE: frozenset({FindingStatus.DISPUTED}),
    FindingStatus.DISPUTED: frozenset(
        {
            FindingStatus.CANDIDATE,
            FindingStatus.CONFIRMED,
            FindingStatus.FALSE_POSITIVE,
            FindingStatus.UNVERIFIABLE,
        }
    ),
    FindingStatus.UNVERIFIABLE: frozenset(
        {
            FindingStatus.CANDIDATE,
            FindingStatus.CONFIRMED,
            FindingStatus.FALSE_POSITIVE,
            FindingStatus.DISPUTED,
        }
    ),
}


def _transition[StateT: StrEnum](
    aggregate: str,
    current: StateT,
    target: StateT,
    transitions: Mapping[StateT, frozenset[StateT]],
) -> StateT:
    if current == target:
        return current
    if target not in transitions[current]:
        raise IllegalTransitionError(aggregate, current, target)
    return target


def transition_task(current: TaskStatus, target: TaskStatus) -> TaskStatus:
    return _transition("task", current, target, TASK_TRANSITIONS)


def transition_job(current: JobStatus, target: JobStatus) -> JobStatus:
    return _transition("job", current, target, JOB_TRANSITIONS)


def transition_run(current: RunStatus, target: RunStatus) -> RunStatus:
    return _transition("run", current, target, RUN_TRANSITIONS)


def transition_poc(current: PocStatus, target: PocStatus) -> PocStatus:
    return _transition("poc", current, target, POC_TRANSITIONS)


def transition_finding(
    current: FindingStatus,
    target: FindingStatus,
    *,
    confirmation: ConfirmationDecision | None = None,
) -> FindingStatus:
    if current is target:
        return current
    transitioned = _transition("finding", current, target, FINDING_TRANSITIONS)
    if target is FindingStatus.CONFIRMED and (confirmation is None or not confirmation.allowed):
        reason_codes = (
            confirmation.reason_codes
            if confirmation is not None
            else ("confirmation_policy_not_evaluated",)
        )
        raise FindingConfirmationError(reason_codes)
    return transitioned
