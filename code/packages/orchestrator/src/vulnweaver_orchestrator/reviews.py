"""Independent-review facts and evidence-driven confirmation gate."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from vulnweaver_contracts import (
    EvidenceRelation,
    EvidenceStrength,
    EvidenceType,
    Finding,
    FindingCategory,
    FindingStatus,
    JsonObject,
    Review,
    ToolIdentity,
)
from vulnweaver_domain import (
    ConfirmationContext,
    ConfirmationDecision,
    EvidenceAssessment,
    evaluate_confirmation,
    transition_finding,
)
from vulnweaver_persistence import Database, Repositories


@dataclass(frozen=True, slots=True)
class ReviewEvidenceFact:
    evidence_id: str
    relation: EvidenceRelation
    evidence_type: EvidenceType
    strength: EvidenceStrength
    artifact_ref: str
    digest: str
    tool: ToolIdentity | None
    command_hash: str | None
    exit_code: int | None
    replay_facts: JsonObject


@dataclass(frozen=True, slots=True)
class ReviewFactContext:
    finding_id: str
    category: FindingCategory
    cwe_id: str
    location: JsonObject
    current_status: FindingStatus
    evidence: tuple[ReviewEvidenceFact, ...]
    review_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ReviewGateResult:
    persisted: bool
    decision: ConfirmationDecision | None
    fact_context: ReviewFactContext


class FindingReviewGate:
    """Build an isolated fact bundle and persist only policy-valid review outcomes."""

    def __init__(self, database: Database) -> None:
        self._database = database

    async def build_fact_context(self, finding_id: str) -> ReviewFactContext:
        async with self._database.transaction() as repositories:
            finding = await repositories.findings.lock_for_review(finding_id)
            return await build_review_fact_context(repositories, finding)

    async def submit(
        self,
        review: Review,
        *,
        established_facts: frozenset[str] = frozenset(),
    ) -> ReviewGateResult:
        async with self._database.transaction() as repositories:
            return await self.submit_in_transaction(
                repositories, review, established_facts=established_facts
            )

    async def submit_in_transaction(
        self,
        repositories: Repositories,
        review: Review,
        *,
        established_facts: frozenset[str] = frozenset(),
    ) -> ReviewGateResult:
        finding = await repositories.findings.lock_for_review(review["finding_id"])
        fact_context = await build_review_fact_context(repositories, finding)
        outcome = FindingStatus(review["outcome"])
        decision: ConfirmationDecision | None = None
        confirmation_allowed = False
        if outcome is FindingStatus.CONFIRMED:
            derived_facts = set(established_facts) - {
                "independent_review_agreement",
                "independent_tool_evidence",
            }
            derived_facts.add("independent_review_agreement")
            if any(
                fact.relation is EvidenceRelation.SUPPORTS
                and fact.evidence_type is EvidenceType.TOOL_OUTPUT
                and fact.tool is not None
                for fact in fact_context.evidence
            ):
                derived_facts.add("independent_tool_evidence")
            decision = evaluate_confirmation(
                ConfirmationContext(
                    category=fact_context.category,
                    evidence=tuple(
                        EvidenceAssessment(
                            evidence_type=fact.evidence_type,
                            strength=fact.strength,
                            reproducible=fact.replay_facts.get("reproducible") is True,
                        )
                        for fact in fact_context.evidence
                        if fact.relation is EvidenceRelation.SUPPORTS
                    ),
                    established_facts=frozenset(derived_facts),
                )
            )
            confirmation_allowed = decision.allowed
            if not confirmation_allowed:
                return ReviewGateResult(False, decision, fact_context)
        transition_finding(finding["status"], outcome, confirmation=decision)
        await repositories.findings.add_review(
            review, confirmation_allowed=confirmation_allowed
        )
        return ReviewGateResult(True, decision, fact_context)


async def build_review_fact_context(
    repositories: Repositories, finding: Finding
) -> ReviewFactContext:
    finding_id = finding["id"]
    relations = await repositories.findings.list_evidence_relations(finding_id)
    facts: list[ReviewEvidenceFact] = []
    for relation in relations:
        evidence = await repositories.evidence.get(relation["evidence_id"])
        if evidence["type"] in {EvidenceType.MODEL_EXPLANATION, EvidenceType.REVIEW_CONCLUSION}:
            continue
        replay_facts = _safe_replay_facts(evidence["type"], evidence["replay_recipe"])
        facts.append(
            ReviewEvidenceFact(
                evidence_id=evidence["id"],
                relation=relation["relation"],
                evidence_type=evidence["type"],
                strength=evidence["strength"],
                artifact_ref=evidence["artifact_ref"],
                digest=evidence["digest"],
                tool=evidence["tool"],
                command_hash=evidence["command_hash"],
                exit_code=evidence["exit_code"],
                replay_facts=replay_facts,
            )
        )
    return ReviewFactContext(
        finding_id=finding_id,
        category=finding["category"],
        cwe_id=finding["cwe_id"],
        location=cast(JsonObject, finding["location"]),
        current_status=finding["status"],
        evidence=tuple(facts),
        review_ids=tuple(finding["review_ids"]),
    )


def _safe_replay_facts(evidence_type: EvidenceType, recipe: JsonObject) -> JsonObject:
    if evidence_type is EvidenceType.MODEL_EXPLANATION:
        return {}
    allowed = {
        key: recipe[key]
        for key in (
            "kind",
            "reproducible",
            "diagnostic_selector",
            "pair_snapshot",
            "result",
        )
        if key in recipe
    }
    return allowed
