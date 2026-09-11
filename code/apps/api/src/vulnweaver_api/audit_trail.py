"""Read-only, evidence-preserving projection of agent and binary analysis activity."""

from __future__ import annotations

import hashlib
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
        if job["kind"] is JobKind.IMPORT
        and isinstance(job.get("tool"), dict)
        and job["tool"].get("name") == "binary-import"
    ]
    return {
        "schema_version": "1.0.0",
        "task_id": task_id,
        "agent_runs": projected_runs,
        "binary_analysis_jobs": binary_jobs,
    }


def _project_run(run: AgentRun, link: _RunLink | None) -> dict[str, Any]:
    role = link.role if link is not None else _standalone_role(str(run["id"]))
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
    def __init__(self, role: str, job_id: str, job_attempt: int, association: str) -> None:
        self.role = role
        self.job_id = job_id
        self.job_attempt = job_attempt
        self.association = association


def _run_links(jobs: Iterable[Job]) -> dict[str, _RunLink]:
    """Index only exact producer-defined identifiers; collisions stay unknown."""

    candidates: dict[str, list[_RunLink]] = {}
    for job in jobs:
        job_id, attempt = str(job["id"]), int(job["attempt"])
        for run_id, role, association in _producer_run_ids(job_id, attempt):
            candidates.setdefault(run_id, []).append(_RunLink(role, job_id, attempt, association))
    return {run_id: links[0] for run_id, links in candidates.items() if len(links) == 1}


def _producer_run_ids(job_id: str, attempt: int) -> tuple[tuple[str, str, str], ...]:
    semantic_base = _stable_id("agent-run", "semantic-audit", job_id, str(attempt))
    return (
        (semantic_base, "semantic_audit", "exact_run_id_rule_with_attempt"),
        (f"{semantic_base}-agent", "semantic_audit_agent", "exact_run_id_rule_with_attempt"),
        (f"agent-run:reverse-plan:{job_id}", "reverse_analysis_planner", "exact_run_id_rule"),
        (
            f"agent-run:readable-pseudocode:{job_id}:{attempt}",
            "readable_pseudocode",
            "exact_run_id_rule_with_attempt",
        ),
        (f"agent-run:harness:{job_id}", "fuzz_harness_generator", "exact_run_id_rule"),
        (
            f"agent-run:key-logic:{hashlib.sha256(job_id.encode()).hexdigest()[:32]}",
            "critical_logic_analyst",
            "exact_run_id_rule",
        ),
        (
            _stable_id("agent-run", "exploit-auto", job_id, str(attempt)),
            "exploit_generator",
            "exact_run_id_rule_with_attempt",
        ),
    )


def _standalone_role(run_id: str) -> str:
    # Independent-review producers encode their role but do not persist a Job
    # association in AgentRun.  Expose only that stated role, never a guessed job.
    return "independent_reviewer" if run_id.startswith("agent-run:review:") else "unknown"


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
