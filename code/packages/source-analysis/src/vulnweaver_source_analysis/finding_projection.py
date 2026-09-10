"""Deterministic projection of static diagnostics into candidate findings."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import cast

from vulnweaver_contracts import (
    ArtifactVersion,
    CallPathStep,
    Evidence,
    EvidenceRelation,
    EvidenceStrength,
    EvidenceType,
    Finding,
    FindingCategory,
    FindingEvidence,
    FindingStatus,
    Job,
    JsonObject,
    PairEdge,
    PairFunction,
    PairNode,
    SchemaVersion,
    SourceLocation,
    StaticAnalysisDiagnostic,
    StaticAnalysisResult,
    ToolIdentity,
)
from vulnweaver_pair import build_call_path_steps
from vulnweaver_persistence import Database, Repositories


@dataclass(frozen=True, slots=True)
class _PairContext:
    """One bounded PAIR read shared by the evidence snapshot and the call path."""

    snapshot: JsonObject
    anchor_function_id: str | None
    neighbourhoods: dict[str, tuple[list[PairFunction], list[PairNode], list[PairEdge]]]


@dataclass(frozen=True, slots=True)
class StaticFindingProjection:
    finding_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]


class StaticFindingProjector:
    """Persist tool facts without importing static-agent reasoning into review input."""

    def __init__(self, database: Database) -> None:
        self._database = database

    async def project(
        self,
        job: Job,
        result: StaticAnalysisResult,
        result_version: ArtifactVersion,
    ) -> StaticFindingProjection:
        finding_ids: set[str] = set()
        evidence_ids: set[str] = set()
        async with self._database.transaction() as repositories:
            for diagnostic in result["diagnostics"]:
                for cwe_id in sorted(set(diagnostic["cwe_ids"])):
                    if not _is_cwe_id(cwe_id):
                        continue
                    pair_context = await _pair_context(repositories, diagnostic["location"])
                    pair_snapshot = pair_context.snapshot
                    finding_id = _finding_id(job["task_id"], cwe_id, diagnostic["location"])
                    evidence_id = _evidence_id(
                        result_version["id"], cwe_id, diagnostic, pair_snapshot
                    )
                    evidence = _evidence(
                        evidence_id,
                        job,
                        result,
                        result_version,
                        diagnostic,
                        cwe_id,
                        pair_snapshot,
                    )
                    await repositories.evidence.create(evidence)
                    finding = _finding(
                        finding_id, job, diagnostic, cwe_id, _call_path(pair_context)
                    )
                    await repositories.findings.upsert_candidate(finding)
                    await repositories.findings.link_evidence(
                        FindingEvidence(
                            schema_version=SchemaVersion.VALUE_1_0_0,
                            finding_id=finding_id,
                            evidence_id=evidence_id,
                            relation=EvidenceRelation.SUPPORTS,
                            weight=0.6,
                            created_by=_tool_source_id(_tool_identity(job)),
                            created_at=result["created_at"],
                        )
                    )
                    finding_ids.add(finding_id)
                    evidence_ids.add(evidence_id)
        return StaticFindingProjection(tuple(sorted(finding_ids)), tuple(sorted(evidence_ids)))


async def _pair_context(repositories: Repositories, location: SourceLocation) -> _PairContext:
    """Read one bounded PAIR neighborhood per enclosing function, once."""

    pair = repositories.pair
    functions: list[PairFunction] = await pair.functions_at_location(
        location["artifact_version_id"], location["path"], location["start_line"]
    )
    function_ids: set[str] = set()
    node_ids: set[str] = set()
    edge_ids: set[str] = set()
    neighbourhoods: dict[str, tuple[list[PairFunction], list[PairNode], list[PairEdge]]] = {}
    for function in functions:
        function_ids.add(function["id"])
        neighborhood = await pair.neighborhood(
            location["artifact_version_id"], function["id"], depth=1
        )
        neighbourhood_functions = cast(list[PairFunction], neighborhood["functions"])
        neighbourhood_nodes = cast(list[PairNode], neighborhood["nodes"])
        neighbourhood_edges = cast(list[PairEdge], neighborhood["edges"])
        neighbourhoods[function["id"]] = (
            neighbourhood_functions,
            neighbourhood_nodes,
            neighbourhood_edges,
        )
        for item in neighbourhood_functions:
            function_ids.add(item["id"])
        for item in neighbourhood_nodes:
            node_ids.add(item["id"])
        for item in neighbourhood_edges:
            edge_ids.add(item["id"])
    snapshot = cast(
        JsonObject,
        {
            "artifact_version_id": location["artifact_version_id"],
            "function_ids": sorted(function_ids),
            "node_ids": sorted(node_ids),
            "edge_ids": sorted(edge_ids),
        },
    )
    return _PairContext(
        snapshot=snapshot,
        anchor_function_id=functions[0]["id"] if functions else None,
        neighbourhoods=neighbourhoods,
    )


def _call_path(context: _PairContext) -> list[CallPathStep]:
    """Project the anchored function's immediate callers and callees."""

    anchor_function_id = context.anchor_function_id
    if anchor_function_id is None:
        return []
    neighbourhood = context.neighbourhoods.get(anchor_function_id)
    if neighbourhood is None:
        return []
    functions, nodes, edges = neighbourhood
    return build_call_path_steps(functions, nodes, edges, anchor_function_id)


def _evidence(
    evidence_id: str,
    job: Job,
    result: StaticAnalysisResult,
    result_version: ArtifactVersion,
    diagnostic: StaticAnalysisDiagnostic,
    cwe_id: str,
    pair_snapshot: JsonObject,
) -> Evidence:
    tool_run = next(
        (item for item in result["tool_runs"] if item["tool_name"] == diagnostic["tool_name"]),
        None,
    )
    replay_recipe = cast(
        JsonObject,
        {
            "kind": "static_analysis_diagnostic",
            "result_artifact_version_id": result_version["id"],
            "diagnostic_selector": {
                "tool_name": diagnostic["tool_name"],
                "rule_id": diagnostic["rule_id"],
                "cwe_id": cwe_id,
                "location": diagnostic["location"],
            },
            "pair_snapshot": pair_snapshot,
            "reproducible": False,
        },
    )
    return Evidence(
        schema_version=SchemaVersion.VALUE_1_0_0,
        id=evidence_id,
        type=EvidenceType.TOOL_OUTPUT,
        strength=EvidenceStrength.SUPPORTING,
        artifact_ref=result_version["object_ref"],
        digest=result_version["digest"],
        tool=_tool_identity(job),
        input_ref=_single_input(job),
        command_hash=_command_hash(job),
        exit_code=tool_run["exit_code"] if tool_run is not None else None,
        stdout_ref=None,
        stderr_ref=None,
        replay_recipe=replay_recipe,
        created_at=result["created_at"],
    )


def _finding(
    finding_id: str,
    job: Job,
    diagnostic: StaticAnalysisDiagnostic,
    cwe_id: str,
    call_path: list[CallPathStep],
) -> Finding:
    return Finding(
        schema_version=SchemaVersion.VALUE_1_0_0,
        id=finding_id,
        task_id=job["task_id"],
        category=_category(cwe_id),
        cwe_id=cwe_id,
        title=f"Static analysis candidate for {cwe_id}",
        severity=diagnostic["severity"],
        confidence=0.6,
        location=diagnostic["location"],
        dataflow=[],
        call_path=call_path,
        status=FindingStatus.CANDIDATE,
        evidence_ids=[],
        review_ids=[],
        poc_ids=[],
        fix_suggestion=f"Review and remediate the code pattern associated with {cwe_id}.",
        created_at=job["created_at"],
    )


def _category(cwe_id: str) -> FindingCategory:
    number = int(cwe_id.removeprefix("CWE-"))
    if number in {119, 120, 121, 122, 124, 125, 126, 127, 415, 416, 476, 787, 788}:
        return FindingCategory.MEMORY_CORRUPTION
    if number in {74, 77, 78, 79, 89, 90, 91, 94, 95, 96, 98, 113, 643, 917}:
        return FindingCategory.INJECTION
    if number in {284, 285, 287, 306, 307, 319, 352, 613, 639, 862, 863}:
        return FindingCategory.AUTH_OR_BUSINESS_LOGIC
    return FindingCategory.STATIC_ONLY


def _finding_id(task_id: str, cwe_id: str, location: SourceLocation) -> str:
    return _stable_id("finding", task_id, cwe_id, _canonical_json(location))


def _evidence_id(
    result_version_id: str,
    cwe_id: str,
    diagnostic: StaticAnalysisDiagnostic,
    pair_snapshot: JsonObject,
) -> str:
    selector = {
        "tool_name": diagnostic["tool_name"],
        "rule_id": diagnostic["rule_id"],
        "cwe_id": cwe_id,
        "location": diagnostic["location"],
        "pair_snapshot": pair_snapshot,
    }
    return _stable_id("evidence", result_version_id, _canonical_json(selector))


def _tool_identity(job: Job) -> ToolIdentity:
    tool = job.get("tool")
    if tool is None:
        raise ValueError("static finding projection requires Job tool identity")
    return tool


def _tool_source_id(tool: ToolIdentity) -> str:
    return _stable_id("tool", tool["name"], tool["version"], tool["image_digest"] or "")


def _single_input(job: Job) -> str:
    if len(job["input_refs"]) != 1:
        raise ValueError("static finding projection requires exactly one input reference")
    return job["input_refs"][0]


def _command_hash(job: Job) -> str:
    descriptor = {
        "tool": _tool_identity(job),
        "arguments": job.get("arguments", {}),
        "input_refs": job["input_refs"],
    }
    digest = hashlib.sha256(_canonical_json(descriptor).encode()).hexdigest()
    return f"sha256:{digest}"


def _is_cwe_id(value: str) -> bool:
    return value.startswith("CWE-") and value[4:].isdigit() and int(value[4:]) > 0


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\0".join(parts).encode()).hexdigest()[:32]
    return f"{prefix}:{digest}"


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
