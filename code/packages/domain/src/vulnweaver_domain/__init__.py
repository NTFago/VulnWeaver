"""VulnWeaver domain rules kept independent from persistence and transport."""

from vulnweaver_domain.aggregation import JobSnapshot, TaskAggregate, aggregate_task
from vulnweaver_domain.idempotency import IdempotencyKeyError, normalize_idempotency_key
from vulnweaver_domain.policies import (
    ConfirmationContext,
    ConfirmationDecision,
    EvidenceAssessment,
    ExploitEligibilityDecision,
    evaluate_confirmation,
    evaluate_exploit_eligibility,
)
from vulnweaver_domain.transitions import (
    FindingConfirmationError,
    IllegalTransitionError,
    transition_finding,
    transition_job,
    transition_poc,
    transition_run,
    transition_task,
)

__all__ = [
    "ConfirmationContext",
    "ConfirmationDecision",
    "EvidenceAssessment",
    "ExploitEligibilityDecision",
    "FindingConfirmationError",
    "IdempotencyKeyError",
    "IllegalTransitionError",
    "JobSnapshot",
    "TaskAggregate",
    "aggregate_task",
    "evaluate_confirmation",
    "evaluate_exploit_eligibility",
    "normalize_idempotency_key",
    "transition_finding",
    "transition_job",
    "transition_poc",
    "transition_run",
    "transition_task",
]
