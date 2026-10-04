"""Derivation of established facts from PoC verification evidence."""

from __future__ import annotations

from typing import cast

from vulnweaver_contracts import (
    EvidenceRelation,
    EvidenceStrength,
    EvidenceType,
    FindingCategory,
    FindingStatus,
    JsonObject,
)
from vulnweaver_orchestrator.reviews import (
    ReviewEvidenceFact,
    ReviewFactContext,
    derive_established_facts,
)


def _fact(
    *,
    evidence_type: EvidenceType,
    strength: EvidenceStrength = EvidenceStrength.STRONG,
    replay_facts: JsonObject | None = None,
) -> ReviewEvidenceFact:
    return ReviewEvidenceFact(
        evidence_id="evidence:test",
        relation=EvidenceRelation.SUPPORTS,
        evidence_type=evidence_type,
        strength=strength,
        artifact_ref="cas://sha256/" + "c" * 64,
        digest="sha256:" + "c" * 64,
        tool=None,
        command_hash=None,
        exit_code=0,
        replay_facts=cast(JsonObject, replay_facts or {}),
    )


def _context(
    category: FindingCategory, evidence: list[ReviewEvidenceFact]
) -> ReviewFactContext:
    return ReviewFactContext(
        finding_id="finding:test",
        category=category,
        cwe_id="CWE-95",
        location={},
        current_status=FindingStatus.CANDIDATE,
        evidence=tuple(evidence),
    )


def test_injection_markers_derive_source_to_sink_and_protection_facts() -> None:
    evidence = _fact(
        evidence_type=EvidenceType.POC_VERIFICATION_RESULT,
        replay_facts={
            "reproducible": True,
            "markers": {
                "sink_reached": True,
                "source": "request.query['expr']",
                "sink": "eval(expr)",
                "protections_observed": ["no input validation"],
            },
        },
    )
    derived = derive_established_facts(_context(FindingCategory.INJECTION, [evidence]))
    assert derived == frozenset(
        {"minimal_reproduction", "source_to_sink_path", "protection_analysis"}
    )


def test_auth_markers_derive_no_confirmation_facts() -> None:
    """RA-02: a behavior difference proves input-dependence, not the invariant.

    No auth fact (constraint_analysis, behavior_difference, reachable_path)
    derives from differential evidence until an executable constraint
    criterion is evaluated by the control plane; the finding stays candidate.
    """

    evidence = _fact(
        evidence_type=EvidenceType.POC_VERIFICATION_RESULT,
        replay_facts={
            "reproducible": True,
            "markers": {
                "behavior_difference": "admin endpoint returns 200 without a session cookie",
                "constraint_digest": "sha256:" + "3" * 64,
            },
        },
    )
    derived = derive_established_facts(
        _context(FindingCategory.AUTH_OR_BUSINESS_LOGIC, [evidence])
    )
    assert derived == frozenset({"minimal_reproduction"})


def test_markers_without_sink_pair_do_not_derive_source_to_sink() -> None:
    evidence = _fact(
        evidence_type=EvidenceType.POC_VERIFICATION_RESULT,
        replay_facts={
            "reproducible": True,
            "markers": {"sink_reached": True, "sink": "eval(expr)"},
        },
    )
    derived = derive_established_facts(_context(FindingCategory.INJECTION, [evidence]))
    assert derived == frozenset({"minimal_reproduction"})


def test_weak_or_non_reproducible_poc_evidence_derives_nothing() -> None:
    weak = _fact(
        evidence_type=EvidenceType.POC_VERIFICATION_RESULT,
        strength=EvidenceStrength.SUPPORTING,
        replay_facts={
            "reproducible": True,
            "markers": {"sink_reached": True, "source": "a", "sink": "b"},
        },
    )
    not_reproducible = _fact(
        evidence_type=EvidenceType.POC_VERIFICATION_RESULT,
        replay_facts={
            "reproducible": False,
            "markers": {"sink_reached": True, "source": "a", "sink": "b"},
        },
    )
    assert derive_established_facts(
        _context(FindingCategory.INJECTION, [weak, not_reproducible])
    ) == frozenset()


def test_auth_markers_do_not_leak_into_injection_category() -> None:
    evidence = _fact(
        evidence_type=EvidenceType.POC_VERIFICATION_RESULT,
        replay_facts={
            "reproducible": True,
            "markers": {"behavior_difference": "admin allows unauthenticated access"},
        },
    )
    derived = derive_established_facts(_context(FindingCategory.INJECTION, [evidence]))
    assert derived == frozenset({"minimal_reproduction"})
