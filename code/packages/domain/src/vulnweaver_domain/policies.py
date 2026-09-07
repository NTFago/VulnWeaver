"""Evidence-driven Finding confirmation policy."""

from __future__ import annotations

from dataclasses import dataclass

from vulnweaver_contracts import (
    EvidenceStrength,
    EvidenceType,
    FindingCategory,
    FindingStatus,
)


@dataclass(frozen=True, slots=True)
class EvidenceAssessment:
    evidence_type: EvidenceType
    strength: EvidenceStrength
    reproducible: bool


@dataclass(frozen=True, slots=True)
class ConfirmationContext:
    category: FindingCategory
    evidence: tuple[EvidenceAssessment, ...]
    established_facts: frozenset[str]


@dataclass(frozen=True, slots=True)
class ConfirmationDecision:
    allowed: bool
    reason_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ExploitEligibilityDecision:
    allowed: bool
    reason_codes: tuple[str, ...]


_REQUIRED_FACTS: dict[FindingCategory, frozenset[str]] = {
    FindingCategory.MEMORY_CORRUPTION: frozenset(
        {"repeatable_crash", "controllable_input", "matching_environment"}
    ),
    FindingCategory.INJECTION: frozenset(
        {"source_to_sink_path", "protection_analysis", "minimal_reproduction"}
    ),
    FindingCategory.AUTH_OR_BUSINESS_LOGIC: frozenset(
        {"reachable_path", "constraint_analysis", "behavior_difference"}
    ),
    FindingCategory.STATIC_ONLY: frozenset(
        {"independent_tool_evidence", "independent_review_agreement"}
    ),
}


def evaluate_confirmation(context: ConfirmationContext) -> ConfirmationDecision:
    """Require category facts plus reproducible non-model strong evidence."""

    reasons: list[str] = []
    missing = sorted(_REQUIRED_FACTS[context.category] - context.established_facts)
    reasons.extend(f"missing_fact:{fact}" for fact in missing)

    strong_reproducible = any(
        item.strength is EvidenceStrength.STRONG
        and item.reproducible
        and item.evidence_type is not EvidenceType.MODEL_EXPLANATION
        for item in context.evidence
    )
    if not strong_reproducible:
        reasons.append("missing_strong_reproducible_evidence")

    return ConfirmationDecision(not reasons, tuple(reasons))


def evaluate_exploit_eligibility(
    finding_status: FindingStatus, *, exploit_validation_enabled: bool
) -> ExploitEligibilityDecision:
    """Gate exploit jobs without broadening the registered project boundary."""

    reasons: list[str] = []
    if finding_status is not FindingStatus.CONFIRMED:
        reasons.append("finding_not_confirmed")
    if not exploit_validation_enabled:
        reasons.append("exploit_validation_disabled")
    return ExploitEligibilityDecision(not reasons, tuple(reasons))
