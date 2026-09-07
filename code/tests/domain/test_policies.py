from __future__ import annotations

import pytest
from vulnweaver_contracts import EvidenceStrength, EvidenceType, FindingCategory, FindingStatus
from vulnweaver_domain import (
    ConfirmationContext,
    EvidenceAssessment,
    evaluate_confirmation,
    evaluate_exploit_eligibility,
)


@pytest.mark.parametrize(
    ("category", "facts"),
    [
        (
            FindingCategory.MEMORY_CORRUPTION,
            {"repeatable_crash", "controllable_input", "matching_environment"},
        ),
        (
            FindingCategory.INJECTION,
            {"source_to_sink_path", "protection_analysis", "minimal_reproduction"},
        ),
        (
            FindingCategory.AUTH_OR_BUSINESS_LOGIC,
            {"reachable_path", "constraint_analysis", "behavior_difference"},
        ),
        (
            FindingCategory.STATIC_ONLY,
            {"independent_tool_evidence", "independent_review_agreement"},
        ),
    ],
)
def test_category_policy_accepts_complete_reproducible_evidence(
    category: FindingCategory, facts: set[str]
) -> None:
    decision = evaluate_confirmation(
        ConfirmationContext(
            category,
            (
                EvidenceAssessment(
                    EvidenceType.REPRODUCTION_RESULT,
                    EvidenceStrength.STRONG,
                    True,
                ),
            ),
            frozenset(facts),
        )
    )
    assert decision.allowed
    assert decision.reason_codes == ()


def test_model_explanation_alone_never_confirms() -> None:
    decision = evaluate_confirmation(
        ConfirmationContext(
            FindingCategory.MEMORY_CORRUPTION,
            (
                EvidenceAssessment(
                    EvidenceType.MODEL_EXPLANATION,
                    EvidenceStrength.STRONG,
                    True,
                ),
            ),
            frozenset({"repeatable_crash", "controllable_input", "matching_environment"}),
        )
    )
    assert not decision.allowed
    assert "missing_strong_reproducible_evidence" in decision.reason_codes


def test_missing_facts_are_reported_deterministically() -> None:
    decision = evaluate_confirmation(
        ConfirmationContext(
            FindingCategory.INJECTION,
            (
                EvidenceAssessment(
                    EvidenceType.DATAFLOW_PATH,
                    EvidenceStrength.STRONG,
                    True,
                ),
            ),
            frozenset({"source_to_sink_path"}),
        )
    )
    assert decision.reason_codes == (
        "missing_fact:minimal_reproduction",
        "missing_fact:protection_analysis",
    )


def test_exploit_requires_confirmed_finding_and_project_opt_in() -> None:
    allowed = evaluate_exploit_eligibility(
        FindingStatus.CONFIRMED, exploit_validation_enabled=True
    )
    assert allowed.allowed

    denied = evaluate_exploit_eligibility(
        FindingStatus.CANDIDATE, exploit_validation_enabled=False
    )
    assert denied.reason_codes == (
        "finding_not_confirmed",
        "exploit_validation_disabled",
    )
