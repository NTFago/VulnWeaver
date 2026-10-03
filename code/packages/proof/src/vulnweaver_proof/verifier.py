"""Independent verdict mapping for trusted execution observations.

The proof entrypoint — system-owned code, not the model — produces one
``VerificationObservation`` per run. This module is the worker-side trust
boundary: it validates that report against the public contract and derives
the PoC result and finding evidence. A verified trigger requires a
target-attributed crash on every replay plus a clean control run; a tool
exit status alone never produces a vulnerability conclusion (ADR-036).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from vulnweaver_contracts import (
    Evidence,
    EvidenceStrength,
    EvidenceType,
    PocResult,
    SchemaVersion,
    VerificationObservation,
    VerificationOutcome,
    validate_contract,
)

REPORT_FILE_NAME = "execution-report.json"
MIN_REPLAY_RUNS = 2
_TIMEOUT_REASONS = frozenset({"driver_timeout", "replay_timeout", "target_timeout"})


class ObservationError(ValueError):
    """Raised when the entrypoint report is missing or not contract-valid."""


def parse_observation(payload: object) -> VerificationObservation:
    """Validate an untrusted report payload into a typed observation."""

    if not isinstance(payload, dict):
        raise ObservationError("execution report must be a JSON object")
    try:
        validate_contract("VerificationObservation", cast(Mapping[str, object], payload))
    except (TypeError, ValueError) as error:
        raise ObservationError("execution report does not satisfy its contract") from error
    return cast(VerificationObservation, payload)


def observation_is_reproducible(observation: VerificationObservation) -> bool:
    """A trigger counts as reproducible only if every replay crashed in-target."""

    total_runs = observation["replay_runs"] + 1
    return (
        observation["replay_runs"] >= MIN_REPLAY_RUNS
        and observation["trigger_runs"] == total_runs
    )


def poc_result_from_observation(observation: VerificationObservation) -> PocResult:
    # The verdict arrives as plain JSON strings, so compare by value.
    verdict = str(observation["verdict"])
    if verdict == VerificationOutcome.VERIFIED_TRIGGER:
        return PocResult.EXPLOITABLE
    if verdict == VerificationOutcome.REJECTED_UNDER_TEST_CONDITIONS:
        return PocResult.NOT_EXPLOITABLE_UNDER_ENVIRONMENT
    if verdict == VerificationOutcome.ENVIRONMENT_ERROR:
        return PocResult.ENVIRONMENT_ERROR
    if _TIMEOUT_REASONS.intersection(observation["verdict_reasons"]):
        return PocResult.TIMEOUT
    return PocResult.INCONCLUSIVE


def evidence_from_observation(
    observation: VerificationObservation,
    *,
    evidence_id: str,
    bundle_ref: str,
    bundle_digest: str,
    stdout_ref: str | None,
    stderr_ref: str | None,
    created_at: str,
) -> Evidence:
    """Build STRONG finding evidence for one verified trigger observation.

    Callers must only invoke this for ``verified_trigger`` verdicts; the
    reproducible flag still records whether replays were stable so the review
    gate can tell deterministic crashes from flaky ones.
    """

    if str(observation["verdict"]) != VerificationOutcome.VERIFIED_TRIGGER:
        raise ValueError("evidence is only derived from verified triggers")
    crashed = next(
        (
            run
            for run in observation["runs"]
            if run["role"] != "control" and run["exit_code"] not in (0, None)
        ),
        None,
    )
    return cast(
        Evidence,
        {
            "schema_version": SchemaVersion.VALUE_1_0_0,
            "id": evidence_id,
            "type": EvidenceType.VERIFICATION_OBSERVATION,
            "strength": EvidenceStrength.STRONG,
            "artifact_ref": bundle_ref,
            "digest": bundle_digest,
            "tool": observation["verifier"],
            "input_ref": bundle_ref,
            "command_hash": observation["driver_digest"],
            "exit_code": None if crashed is None else crashed["exit_code"],
            "stdout_ref": stdout_ref,
            "stderr_ref": stderr_ref,
            "replay_recipe": {
                "kind": "verification_observation",
                "reproducible": observation_is_reproducible(observation),
                "observation": dict(observation),
            },
            "created_at": created_at,
        },
    )
