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

    return (
        observation_is_consistent(observation)
        and str(observation["verdict"]) == VerificationOutcome.VERIFIED_TRIGGER
        and observation["replay_runs"] == MIN_REPLAY_RUNS
        and observation["trigger_runs"] >= MIN_REPLAY_RUNS + 1
    )


def observation_is_consistent(observation: VerificationObservation) -> bool:
    """Check that the verdict and counters follow from the recorded runs."""

    runs = observation["runs"]
    if any(run["target_frames"] and (run["timed_out"] or not _run_crashed(run)) for run in runs):
        return False
    control = [run for run in runs if run["role"] == "control"]
    trigger = [run for run in runs if run["role"] == "trigger"]
    replay = [run for run in runs if run["role"] == "replay"]
    if not control or observation["replay_runs"] != len(replay):
        return False
    if observation["trigger_runs"] != sum(
        1 for run in (*trigger, *replay) if _run_attributed(run)
    ):
        return False

    timed_out = any(run["timed_out"] for run in runs)
    trigger_failure = next((run for run in trigger if _run_attributed(run)), None)
    if timed_out:
        verdict, reasons = VerificationOutcome.INCONCLUSIVE, ["target_timeout"]
    elif any(_run_crashed(run) for run in control):
        verdict, reasons = VerificationOutcome.REJECTED_UNDER_TEST_CONDITIONS, [
            "control_input_failed"
        ]
    elif trigger_failure is None:
        verdict = VerificationOutcome.REJECTED_UNDER_TEST_CONDITIONS
        reasons = [
            "target_not_involved" if any(_run_crashed(run) for run in trigger)
            else "no_trigger_observed"
        ]
    elif (
        len(replay) == MIN_REPLAY_RUNS
        and all(_run_attributed(run) for run in replay)
        and all(run["input_name"] == trigger_failure["input_name"] for run in replay)
    ):
        verdict = VerificationOutcome.VERIFIED_TRIGGER
        reasons = ["target_exception_attributed", "control_input_clean", "replay_stable"]
    else:
        verdict, reasons = VerificationOutcome.INCONCLUSIVE, ["non_deterministic_trigger"]
    return (
        str(observation["verdict"]) == str(verdict)
        and list(observation["verdict_reasons"]) == reasons
    )


def _run_crashed(run: Mapping[str, object]) -> bool:
    exit_code = run["exit_code"]
    return (exit_code is not None and exit_code != 0) or run["signal"] is not None


def _run_attributed(run: Mapping[str, object]) -> bool:
    return _run_crashed(run) and bool(run["target_frames"]) and not bool(run["timed_out"])


def poc_result_from_observation(observation: VerificationObservation) -> PocResult:
    # The verdict arrives as plain JSON strings, so compare by value.
    verdict = str(observation["verdict"])
    if verdict == VerificationOutcome.VERIFIED_TRIGGER:
        # The current verifier observes a repeatable Python exception in the
        # selected target function. That is useful behavior evidence, but it
        # does not establish security impact or an exploitable crash.
        return PocResult.INCONCLUSIVE
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
    created_at: str,
) -> Evidence:
    """Build SUPPORTING evidence for one reproducible target-exception observation.

    A repeated exception is recorded for diagnosis, but does not prove a
    vulnerability impact. The review gate must not derive crash facts from it.
    """

    if not observation_is_reproducible(observation):
        raise ValueError("evidence is only derived from verified triggers")
    crashed = next(
        (
            run
            for run in observation["runs"]
            if run["role"] != "control" and run["exit_code"] not in (0, None)
        ),
        None,
    )
    stable_observation = {
        **observation,
        "runs": [
            {**run, "duration_millis": 0}
            for run in observation["runs"]
        ],
    }
    return cast(
        Evidence,
        {
            "schema_version": SchemaVersion.VALUE_1_0_0,
            "id": evidence_id,
            "type": EvidenceType.VERIFICATION_OBSERVATION,
            "strength": EvidenceStrength.SUPPORTING,
            "artifact_ref": bundle_ref,
            "digest": bundle_digest,
            "tool": observation["verifier"],
            "input_ref": bundle_ref,
            "command_hash": observation["driver_digest"],
            "exit_code": None if crashed is None else crashed["exit_code"],
            # The canonical POC record retains the first execution log. These
            # references vary on a lease retry and are not part of the finding
            # evidence identity.
            "stdout_ref": None,
            "stderr_ref": None,
            "replay_recipe": {
                "kind": "verification_observation",
                "reproducible": observation_is_reproducible(observation),
                "observation": stable_observation,
            },
            "created_at": created_at,
        },
    )
