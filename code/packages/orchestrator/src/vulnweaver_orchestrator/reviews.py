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
    TargetBinding,
    ToolIdentity,
    validate_contract,
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


def derive_established_facts(fact_context: ReviewFactContext) -> frozenset[str]:
    """Facts that the linked evidence itself establishes.

    ``FindingPolicy`` lists the facts a confirmed finding must have, but nothing
    used to derive them from evidence, so every memory-corruption, injection and
    authentication finding was unconfirmable no matter how much proof was
    attached. This closes that gap without weakening the policy: the required
    facts and the strong-reproducible-evidence rule are unchanged, and each fact
    below is derived only from a SUPPORTS relation whose evidence is strong,
    reproducible and non-model.

    The mapping is deliberately narrow. A reproduced crash proves the fault
    repeats in the matched environment and that its recorded input drives it; it
    does not prove a source-to-sink path or a reachable authentication bypass, so
    injection and business-logic findings stay unconfirmable on a crash alone.

    ``POC_VERIFICATION_RESULT`` closes that gap for sandbox-run PoC scripts: the
    markers were captured by the sandbox harness from an actual execution against
    the sample, so ``sink_reached`` with a concrete source/sink pair proves the
    source-to-sink path, an observed protection list proves protection analysis
    happened against the live sample, and a recorded behavior difference proves a
    reachable path with divergent outcomes. Model explanations never enter this
    branch, so the "model cannot self-confirm" rule is preserved.

    ``VERIFICATION_OBSERVATION`` is the target-bound successor (ADR-036): the
    trusted entrypoint observed an exception from compiled original target code
    with a clean control input and stable
    replays. That carries the digest-bound crafted input and the binding to the
    exact sample version, so a memory-corruption finding gets the full crash
    fact set; other categories only get the minimal reproduction because a crash
    alone still proves no source-to-sink path or authorization constraint.
    """

    derived: set[str] = set()
    for fact in fact_context.evidence:
        if fact.relation is not EvidenceRelation.SUPPORTS:
            continue
        if fact.evidence_type is EvidenceType.MODEL_EXPLANATION:
            continue
        if fact.strength is not EvidenceStrength.STRONG:
            continue
        reproducible = fact.replay_facts.get("reproducible") is True
        if fact.evidence_type is EvidenceType.CRASH_RECORD and reproducible:
            derived.update({"repeatable_crash", "matching_environment"})
            if fact.artifact_ref:
                # The crashing input is materialized in CAS, so it is a concrete
                # input the fault was actually driven with.
                derived.add("controllable_input")
        elif fact.evidence_type is EvidenceType.REPRODUCTION_RESULT and reproducible:
            derived.add("minimal_reproduction")
        elif fact.evidence_type is EvidenceType.POC_VERIFICATION_RESULT and reproducible:
            derived.update(_derived_poc_facts(fact, fact_context.category))
        elif fact.evidence_type is EvidenceType.VERIFICATION_OBSERVATION and reproducible:
            derived.update(_derived_observation_facts(fact, fact_context.category))
    return frozenset(derived)


def _derived_observation_facts(
    fact: ReviewEvidenceFact, category: FindingCategory
) -> set[str]:
    derived = {"minimal_reproduction"}
    observation = fact.replay_facts.get("observation")
    if not isinstance(observation, dict) or observation.get("verdict") != "verified_trigger":
        return derived
    if category is FindingCategory.MEMORY_CORRUPTION:
        # verified_trigger already encodes an attributed target crash on every
        # replay with a clean control input; the inputs array carries the
        # digest-bound attacker input that drove it.
        derived.update({"repeatable_crash", "matching_environment", "controllable_input"})
    return derived


def _derived_poc_facts(
    fact: ReviewEvidenceFact, category: FindingCategory
) -> set[str]:
    derived = {"minimal_reproduction"}
    markers = fact.replay_facts.get("markers")
    if not isinstance(markers, dict):
        return derived
    if category is FindingCategory.INJECTION:
        source = markers.get("source")
        sink = markers.get("sink")
        if (
            markers.get("sink_reached") is True
            and isinstance(source, str)
            and source
            and isinstance(sink, str)
            and sink
        ):
            derived.add("source_to_sink_path")
        protections = markers.get("protections_observed")
        if isinstance(protections, list) and protections:
            derived.add("protection_analysis")
    elif category is FindingCategory.AUTH_OR_BUSINESS_LOGIC:
        difference = markers.get("behavior_difference")
        if isinstance(difference, str) and difference:
            derived.update({"behavior_difference", "reachable_path"})
    return derived


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
            derived_facts |= derive_established_facts(fact_context)
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
        await repositories.findings.add_review(review, confirmation_allowed=confirmation_allowed)
        return ReviewGateResult(True, decision, fact_context)


async def build_review_fact_context(
    repositories: Repositories, finding: Finding
) -> ReviewFactContext:
    finding_id = finding["id"]
    target_version = await repositories.artifacts.get_version(
        finding["location"]["artifact_version_id"]
    )
    target_artifact = await repositories.artifacts.get(target_version["artifact_id"])
    expected_binding = cast(
        TargetBinding,
        {
            "artifact_id": target_artifact["id"],
            "version_id": target_version["id"],
            "artifact_kind": target_artifact["kind"],
            "digest": target_version["digest"],
        },
    )
    relations = await repositories.findings.list_evidence_relations(finding_id)
    facts: list[ReviewEvidenceFact] = []
    for relation in relations:
        evidence = await repositories.evidence.get(relation["evidence_id"])
        if evidence["type"] in {EvidenceType.MODEL_EXPLANATION, EvidenceType.REVIEW_CONCLUSION}:
            continue
        if evidence["type"] is EvidenceType.VERIFICATION_OBSERVATION:
            recipe = evidence["replay_recipe"]
            observation = recipe.get("observation")
            if not isinstance(observation, dict):
                continue
            try:
                validate_contract("VerificationObservation", observation)
            except (TypeError, ValueError):
                continue
            observed_binding = observation.get("target_binding")
            if not isinstance(observed_binding, dict) or any(
                observed_binding.get(key) != expected_binding.get(key)
                for key in ("artifact_id", "version_id", "artifact_kind", "digest")
            ):
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
    if evidence_type is EvidenceType.VERIFICATION_OBSERVATION:
        # The typed observation is contract-validated before it may carry any
        # weight; anything malformed degrades to an unusable empty recipe.
        observation = recipe.get("observation")
        if isinstance(observation, dict):
            try:
                validate_contract("VerificationObservation", observation)
            except (TypeError, ValueError):
                observation = None
        else:
            observation = None
        allowed = {
            key: recipe[key]
            for key in ("kind", "reproducible")
            if key in recipe
        }
        if observation is not None:
            allowed["observation"] = observation
        return allowed
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
