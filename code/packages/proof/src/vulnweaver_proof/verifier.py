"""Independent verdict mapping for trusted execution observations.

The proof entrypoint — system-owned code, not the model — produces one
``VerificationObservation`` per run. This module is the worker-side trust
boundary: it validates that report against the public contract and derives
the PoC result and finding evidence. A verified trigger requires a
target-attributed crash on every replay plus a clean control run; a tool
exit status alone never produces a vulnerability conclusion (ADR-036).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import cast

from vulnweaver_contracts import (
    Evidence,
    EvidenceStrength,
    EvidenceType,
    JsonObject,
    JsonValue,
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
        behavior_trigger = next((run for run in trigger if _run_completed(run)), None)
        behavior_replay = (
            len(replay) == MIN_REPLAY_RUNS and all(_run_completed(run) for run in replay)
        )
        behavior = observation.get("observed_behavior")
        if (
            behavior_trigger is not None
            and behavior_replay
            and isinstance(behavior, dict)
            and behavior.get("differed") is True
            and behavior.get("replay_consistent") is True
            and _behavior_matches_runs(behavior, behavior_trigger, control, replay)
        ):
            verdict = VerificationOutcome.VERIFIED_BEHAVIOR
            reasons = [
                "behavior_difference_observed",
                "control_input_clean",
                "replay_stable",
            ]
        elif any(_run_crashed(run) for run in trigger):
            verdict = VerificationOutcome.REJECTED_UNDER_TEST_CONDITIONS
            reasons = ["target_not_involved"]
        elif behavior_trigger is not None and behavior_replay:
            # The entrypoint distinguishes "no comparable output" from "no
            # difference" by digest presence; mirror that exactly.
            comparable = (
                behavior_trigger.get("output_digest") is not None
                and all(run.get("output_digest") is not None for run in replay)
                and any(run.get("output_digest") is not None for run in control)
            )
            verdict = VerificationOutcome.REJECTED_UNDER_TEST_CONDITIONS
            reasons = ["no_behavior_difference" if comparable else "no_trigger_observed"]
        else:
            verdict = VerificationOutcome.REJECTED_UNDER_TEST_CONDITIONS
            reasons = ["no_trigger_observed"]
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


def _run_completed(run: Mapping[str, object]) -> bool:
    return run["exit_code"] == 0 and not bool(run["timed_out"])


def _behavior_matches_runs(
    behavior: Mapping[str, object],
    behavior_trigger: Mapping[str, object],
    control: Sequence[Mapping[str, object]],
    replay: Sequence[Mapping[str, object]],
) -> bool:
    """The claimed behavior must equal the digests the runs themselves recorded."""

    crafted = behavior_trigger.get("output_digest")
    control_digest = next(
        (run.get("output_digest") for run in control if _run_completed(run)), None
    )
    replay_digests = {run.get("output_digest") for run in replay}
    return (
        isinstance(crafted, str)
        and isinstance(control_digest, str)
        and behavior.get("crafted_output_digest") == crafted
        and behavior.get("control_output_digest") == control_digest
        and replay_digests == {crafted}
    )


def behavior_is_verified(observation: VerificationObservation) -> bool:
    """A stable, supervisor-computed output difference between crafted and control.

    The original target ran to completion under the crafted input with output
    that (a) differs from the control run and (b) reproduces byte-for-byte on
    every replay. That is input-dependent behavior of the bound target — the
    honest oracle behind the auth/injection policy facts — and it never claims
    a crash or security impact by itself.
    """

    return (
        observation_is_consistent(observation)
        and str(observation["verdict"]) == VerificationOutcome.VERIFIED_BEHAVIOR
    )


def _run_crashed(run: Mapping[str, object]) -> bool:
    exit_code = run["exit_code"]
    return (exit_code is not None and exit_code != 0) or run["signal"] is not None


def _run_attributed(run: Mapping[str, object]) -> bool:
    return _run_crashed(run) and bool(run["target_frames"]) and not bool(run["timed_out"])


def poc_result_from_observation(observation: VerificationObservation) -> PocResult:
    # The verdict arrives as plain JSON strings, so compare by value.
    verdict = str(observation["verdict"])
    if verdict in {
        VerificationOutcome.VERIFIED_TRIGGER,
        VerificationOutcome.VERIFIED_BEHAVIOR,
    }:
        # The current verifier observes a repeatable Python exception in the
        # selected target function, or a repeatable output difference. Both
        # are useful behavior evidence, but neither establishes security
        # impact or an exploitable crash.
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
    """Build SUPPORTING evidence for one reproducible target-observation.

    A repeated exception or a repeated output difference is recorded for
    diagnosis, but does not prove a vulnerability impact. The review gate must
    not derive crash facts from it.
    """

    if not (
        observation_is_reproducible(observation) or behavior_is_verified(observation)
    ):
        raise ValueError("evidence is only derived from verified observations")
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
                "reproducible": True,
                "observation": stable_observation,
            },
            "created_at": created_at,
        },
    )


def differential_evidence_from_observation(
    observation: VerificationObservation,
    *,
    evidence_id: str,
    finding_category: str,
    finding_constraint_digest: str | None,
    bundle_ref: str,
    bundle_digest: str,
    created_at: str,
    protections_observed: list[str] | None = None,
) -> Evidence | None:
    """STRONG record of a supervisor-verified output difference (CR-04).

    The markers below are not model claims and not target self-reports: every
    value is derived from the trusted entrypoint's own observation after the
    worker validated it against the bundle. ``constraint_digest`` binds the
    probe to the constraint registered on the finding; when the observation
    carries no matching digest the auth fact is withheld. For injection,
    ``protections_observed`` carries the deterministic control-plane protection
    enumeration over the digest-bound target source.
    """

    if not behavior_is_verified(observation):
        return None
    behavior = observation.get("observed_behavior")
    if not isinstance(behavior, dict):
        return None
    constraint_digest = observation.get("constraint_digest")
    constraint_bound = (
        isinstance(constraint_digest, str)
        and bool(constraint_digest)
        and constraint_digest == finding_constraint_digest
    )
    category = finding_category.removeprefix("FindingCategory.")
    markers: JsonObject
    if category == "auth_or_business_logic":
        if not constraint_bound:
            # Without the bound constraint the run proves input-dependence but
            # says nothing about the registered security invariant.
            return None
        markers = {
            "behavior_difference": (
                f"crafted output {behavior['crafted_output_digest']} != "
                f"control output {behavior['control_output_digest']}"
            ),
            "constraint_digest": constraint_digest,
        }
    elif category == "injection":
        markers = {
            "sink_reached": True,
            "source": "crafted_input",
            "sink": f"target_callable@{observation['target_binding']['digest']}",
        }
        if protections_observed:
            markers["protections_observed"] = cast(JsonValue, protections_observed)
    else:
        # Differential output says nothing about memory corruption or
        # static-only findings; no record is honest there.
        return None
    return cast(
        Evidence,
        {
            "schema_version": SchemaVersion.VALUE_1_0_0,
            "id": evidence_id,
            "type": EvidenceType.POC_VERIFICATION_RESULT,
            "strength": EvidenceStrength.STRONG,
            "artifact_ref": bundle_ref,
            "digest": bundle_digest,
            "tool": observation["verifier"],
            "input_ref": bundle_ref,
            "command_hash": observation["driver_digest"],
            "exit_code": 0,
            "stdout_ref": None,
            "stderr_ref": None,
            "replay_recipe": {
                "kind": "poc_verification_result",
                "reproducible": True,
                "markers": markers,
            },
            "created_at": created_at,
        },
    )
