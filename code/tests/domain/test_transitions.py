from __future__ import annotations

import pytest
from vulnweaver_contracts import FindingStatus, JobStatus, PocStatus, RunStatus, TaskStatus
from vulnweaver_domain import (
    ConfirmationDecision,
    FindingConfirmationError,
    IllegalTransitionError,
    transition_finding,
    transition_job,
    transition_poc,
    transition_run,
    transition_task,
)
from vulnweaver_domain.transitions import (
    FINDING_TRANSITIONS,
    JOB_TRANSITIONS,
    POC_TRANSITIONS,
    RUN_TRANSITIONS,
    TASK_TRANSITIONS,
)


@pytest.mark.parametrize(
    ("transition", "transitions"),
    [
        (transition_task, TASK_TRANSITIONS),
        (transition_job, JOB_TRANSITIONS),
        (transition_run, RUN_TRANSITIONS),
        (transition_poc, POC_TRANSITIONS),
    ],
)
def test_every_declared_transition_is_accepted(transition: object, transitions: object) -> None:
    for current, targets in transitions.items():  # type: ignore[union-attr]
        assert transition(current, current) == current  # type: ignore[operator]
        for target in targets:
            assert transition(current, target) == target  # type: ignore[operator]


@pytest.mark.parametrize(
    ("transition", "current", "target"),
    [
        (transition_task, TaskStatus.COMPLETED, TaskStatus.ANALYZING),
        (transition_job, JobStatus.SUCCEEDED, JobStatus.RUNNING),
        (transition_run, RunStatus.FAILED, RunStatus.RUNNING),
        (transition_poc, PocStatus.COMPLETED, PocStatus.RUNNING),
        (transition_finding, FindingStatus.CONFIRMED, FindingStatus.CANDIDATE),
    ],
)
def test_illegal_transition_is_structured(
    transition: object, current: object, target: object
) -> None:
    with pytest.raises(IllegalTransitionError) as captured:
        transition(current, target)  # type: ignore[operator]
    assert captured.value.current is current
    assert captured.value.target is target


def test_failed_job_can_only_retry_through_queue() -> None:
    assert transition_job(JobStatus.FAILED, JobStatus.QUEUED) is JobStatus.QUEUED
    with pytest.raises(IllegalTransitionError):
        transition_job(JobStatus.FAILED, JobStatus.RUNNING)


def test_every_declared_finding_transition_is_accepted_with_policy() -> None:
    allowed = ConfirmationDecision(True, ())
    for current, targets in FINDING_TRANSITIONS.items():
        assert transition_finding(current, current) is current
        for target in targets:
            confirmation = allowed if target is FindingStatus.CONFIRMED else None
            assert transition_finding(current, target, confirmation=confirmation) is target


def test_confirmation_requires_an_explicit_successful_policy_decision() -> None:
    with pytest.raises(FindingConfirmationError) as missing:
        transition_finding(FindingStatus.CANDIDATE, FindingStatus.CONFIRMED)
    assert missing.value.reason_codes == ("confirmation_policy_not_evaluated",)

    denied = ConfirmationDecision(False, ("missing_strong_reproducible_evidence",))
    with pytest.raises(FindingConfirmationError) as rejected:
        transition_finding(
            FindingStatus.CANDIDATE,
            FindingStatus.CONFIRMED,
            confirmation=denied,
        )
    assert rejected.value.reason_codes == ("missing_strong_reproducible_evidence",)
