"""Read-only, evidence-preserving projection of agent and binary analysis activity."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from typing import Any

from vulnweaver_contracts import AgentRun, Job, JobKind, WorkerResult

_SUCCESS_STEP = re.compile(r"^step (?P<step_id>[^ ]+) via (?P<tool>[^ ]+)$")
_FAILED_STEP = re.compile(r"^step (?P<step_id>[^ ]+) failed: (?P<failure_code>.+)$")


def build_audit_trail(
    *,
    task_id: str,
    runs: Iterable[AgentRun],
    jobs: Iterable[Job],
    results: Mapping[str, WorkerResult | None],
) -> dict[str, Any]:
    """Return display metadata without mutating or reinterpreting source records.

    AgentRun deliberately has no job_id or role fields.  Associations are therefore
    emitted only when an existing producer's deterministic run-id rule exactly
    reproduces the stored id.  The model name is never an association input.
    """

    job_items = tuple(jobs)
    links = _run_links(job_items)
    projected_runs = [_project_run(run, links.get(str(run["id"]))) for run in runs]
    binary_jobs = [
        {
            "job_id": job["id"],
            "status": str(job["status"]),
            "attempt": job["attempt"],
            "input_refs": list(job["input_refs"]),
            "output_version_ids": list(
                (results.get(str(job["id"])) or {}).get("produced_artifact_version_ids", [])
            ),
            # Job results establish the analysis Job and its output references.
            # They do not themselves contain unpacking/decompilation facts; those
            # live in the immutable binary-analysis artifact and are intentionally
            # not guessed or read by this bounded API projection.
            "facts_status": "not_exposed",
        }
        for job in job_items
        if _is_binary_import(job)
    ]
    return {
        "schema_version": "1.0.0",
        "task_id": task_id,
        "agent_runs": projected_runs,
        "binary_analysis_jobs": binary_jobs,
    }


def _project_run(run: AgentRun, link: _RunLink | None) -> dict[str, Any]:
    role = link.role if link is not None else "unknown"
    association = link.association if link is not None else "unknown"
    job_id = link.job_id if link is not None else None
    job_attempt = link.job_attempt if link is not None else None
    return {
        "id": run["id"],
        "status": str(run["status"]),
        "model": run["model"],
        "prompt_hash": run["prompt_hash"],
        "input_refs": list(run["input_refs"]),
        "result_refs": list(run.get("result_refs", [])),
        "token_usage": dict(run["token_usage"]),
        "duration_ms": run.get("duration_ms"),
        "failure": run["failure"],
        "created_at": run["created_at"],
        "updated_at": run["updated_at"],
        "role": role,
        "job_id": job_id,
        "job_attempt": job_attempt,
        "association": association,
        "decisions": [dict(item) for item in run["decisions"]],
        "tool_steps": _tool_steps(run),
    }


class _RunLink:
    def __init__(
        self, role: str, job_id: str, job_attempt: int | None, association: str
    ) -> None:
        self.role = role
        self.job_id = job_id
        self.job_attempt = job_attempt
        self.association = association


def _run_links(jobs: Iterable[Job]) -> dict[str, _RunLink]:
    """Index only exact producer-defined identifiers; collisions stay unknown."""

    candidates: dict[str, list[_RunLink]] = {}
    for job in jobs:
        job_id = str(job["id"])
        for run_id, role, job_attempt, association in _producer_run_ids(job):
            candidates.setdefault(run_id, []).append(
                _RunLink(role, job_id, job_attempt, association)
            )
    return {run_id: links[0] for run_id, links in candidates.items() if len(links) == 1}


def _producer_run_ids(job: Job) -> tuple[tuple[str, str, int | None, str], ...]:
    """Return IDs emitted by producers that this exact Job can execute.

    Rules that encode an attempt bind only the attempt currently stored on the
    Job; a historic AgentRun cannot be reconstructed after a retry and remains
    unassociated.  Producers whose IDs omit an attempt still identify the Job,
    but deliberately report ``job_attempt=None``.
    """

    job_id, attempt = str(job["id"]), int(job["attempt"])
    if job["kind"] is JobKind.SEMANTIC_AUDIT:
        semantic_base = _stable_id("agent-run", "semantic-audit", job_id, str(attempt))
        return (
            (semantic_base, "semantic_audit", attempt, "exact_run_id_rule_with_attempt"),
            (
                f"{semantic_base}-agent",
                "semantic_audit_agent",
                attempt,
                "exact_run_id_rule_with_attempt",
            ),
        )
    if _is_binary_import(job):
        return (
            (
                f"agent-run:reverse-plan:{job_id}",
                "reverse_analysis_planner",
                None,
                "exact_run_id_rule",
            ),
            (
                f"agent-run:readable-pseudocode:{job_id}:{attempt}",
                "readable_pseudocode",
                attempt,
                "exact_run_id_rule_with_attempt",
            ),
            (
                f"agent-run:key-logic:{hashlib.sha256(job_id.encode()).hexdigest()[:32]}",
                "critical_logic_analyst",
                None,
                "exact_run_id_rule",
            ),
        )
    if job["kind"] is JobKind.FUZZ and _has_harness_context(job):
        harness_job_id = f"{job_id}:attempt:{attempt}"
        return (
            (
                f"agent-run:harness:{harness_job_id}",
                "fuzz_harness_generator",
                attempt,
                "exact_run_id_rule_with_attempt",
            ),
            *(
                (
                    f"agent-run:harness:{harness_job_id}:repair:{repair_round}",
                    "fuzz_harness_generator",
                    attempt,
                    "exact_run_id_rule_with_attempt",
                )
                for repair_round in range(9)
            ),
        )
    if job["kind"] is JobKind.EXPLOIT and _is_auto_exploit(job):
        return (
            (
                _stable_id("agent-run", "exploit-auto", job_id, str(attempt)),
                "exploit_generator",
                attempt,
                "exact_run_id_rule_with_attempt",
            ),
        )
    if job["kind"] is JobKind.REVIEW:
        review_run_id = _review_run_id(job_id, attempt, job.get("arguments"))
        return (
            (review_run_id, "independent_reviewer", attempt, "exact_run_id_rule_with_attempt"),
        ) if review_run_id is not None else ()
    return ()


def _is_binary_import(job: Job) -> bool:
    tool = job.get("tool")
    return (
        job["kind"] is JobKind.IMPORT
        and isinstance(tool, Mapping)
        and tool.get("name") == "binary-import"
    )


def _is_auto_exploit(job: Job) -> bool:
    arguments = job.get("arguments")
    return isinstance(arguments, Mapping) and isinstance(arguments.get("auto_exploit"), Mapping)


def _has_harness_context(job: Job) -> bool:
    arguments = job.get("arguments")
    return isinstance(arguments, Mapping) and isinstance(arguments.get("harness_context"), Mapping)


def _review_run_id(
    job_id: str, attempt: int, arguments: Mapping[str, object] | None
) -> str | None:
    if arguments is None:
        return None
    finding_id = arguments.get("finding_id")
    if not isinstance(finding_id, str) or not finding_id:
        return None
    attempt_key = f"{job_id}:attempt:{attempt}"
    identity = hashlib.sha256(
        json.dumps(
            [finding_id, attempt_key], ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    return f"agent-run:review:{identity}"


def _tool_steps(run: AgentRun) -> list[dict[str, Any]]:
    """Extract only persisted loop decisions; observations were not persisted."""

    steps: list[dict[str, Any]] = []
    for decision in run["decisions"]:
        reason = str(decision["reason"])
        success = _SUCCESS_STEP.fullmatch(reason)
        if success is not None and decision["decision"] == "step_executed":
            steps.append(
                {
                    "step_id": success["step_id"],
                    "tool": success["tool"],
                    "succeeded": True,
                    "failure_code": None,
                    "observation": None,
                    "observation_status": "not_recorded",
                }
            )
            continue
        failed = _FAILED_STEP.fullmatch(reason)
        if failed is not None and decision["decision"] == "step_failed":
            failure_code = failed["failure_code"]
            steps.append(
                {
                    "step_id": failed["step_id"],
                    "tool": None,
                    "succeeded": False,
                    "failure_code": None if failure_code == "None" else failure_code,
                    "observation": None,
                    "observation_status": "not_recorded",
                }
            )
    return steps


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\0".join(parts).encode()).hexdigest()[:32]
    return f"{prefix}:{digest}"
