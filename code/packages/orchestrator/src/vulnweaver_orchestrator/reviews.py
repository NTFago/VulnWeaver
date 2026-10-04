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

    ``POC_VERIFICATION_RESULT`` markers were previously mapped to injection and
    auth confirmation facts. That mapping is withdrawn (RA-02, RG-01/RG-02):
    the sink observation reaches the supervisor through the target's own exit
    status, which the target can forge or suppress, and a lexicon sink firing
    does not prove the crafted input propagated into it. Markers remain in the
    evidence as diagnostics; until a target-unforgeable observation and an
    executable propagation/constraint criterion exist (see
    code/docs/oracle-proposal-2026-10-04.md), differential POC evidence
    establishes only a minimal reproduction, and injection/auth findings stay
    candidates. Model explanations never enter this branch, so the "model
    cannot self-confirm" rule is preserved.

    ``VERIFICATION_OBSERVATION`` records a repeatable exception from the exact
    target version. That is diagnostic behavior, not proof of security impact;
    it must not supply crash, controllability, or environment facts used to
    confirm a memory-corruption finding.
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
            derived.update(_derived_observation_facts())
    return frozenset(derived)


def _derived_observation_facts() -> set[str]:
    return {"minimal_reproduction"}


def _derived_poc_facts(
    fact: ReviewEvidenceFact, category: FindingCategory
) -> set[str]:
    """Differential POC evidence establishes only a minimal reproduction.

    RG-01/RG-02 (2026-10-04 review): the in-process sink observation reaches
    the supervisor via the target's own exit status — a channel the target can
    forge (`os._exit(20)`) or suppress (`sys.setprofile(None)`) — and a lexicon
    sink firing says nothing about the crafted input propagating into it. Until
    a target-unforgeable observation and an input-propagation criterion exist,
    ``sink_reached``/``protections_observed`` markers are diagnostics only and
    derive no injection confirmation facts; the same holds for auth markers
    (RA-02). Injection and auth findings therefore stay candidates, and
    confirmation requires the crash oracle (P0.5) or an executable constraint/
    propagation criterion adopted via ADR.
    """

    del category  # derivation is category-independent until trusted criteria exist
    derived = {"minimal_reproduction"}
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
            # CR-04: POC verification results carry the typed markers the proof
            # worker derived from its own validated observation. Model output
            # never writes this evidence type, so the markers are machine facts.
            "markers",
        )
        if key in recipe
    }
    return allowed
