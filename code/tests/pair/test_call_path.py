from __future__ import annotations

import asyncio
from typing import cast

import pytest
from vulnweaver_contracts import (
    BinaryLocation,
    JsonObject,
    PairEdge,
    PairEdgeType,
    PairFunction,
    PairNode,
    PairNodeKind,
    SchemaVersion,
    SourceImportResult,
    SourceLocation,
    ToolIdentity,
)
from vulnweaver_pair import PairQueryService, SourcePairImporter, build_call_path_steps
from vulnweaver_persistence import Database, DatabaseSettings

from tests.persistence.factories import artifact, artifact_version, project

_VERSION = "artifact-version:call-path"


def _function(
    name: str,
    *,
    function_id: str | None = None,
    path: str | None = None,
    line: int | None = None,
    address: int | None = None,
) -> PairFunction:
    source: SourceLocation | None = (
        SourceLocation(
            artifact_version_id=_VERSION,
            path=path,
            start_line=line,
            start_column=1,
            end_line=line + 1,
            end_column=1,
        )
        if path is not None and line is not None
        else None
    )
    binary: BinaryLocation | None = (
        BinaryLocation(
            artifact_version_id=_VERSION,
            virtual_address=address,
            file_offset=None,
        )
        if address is not None
        else None
    )
    return PairFunction(
        schema_version=SchemaVersion.VALUE_1_0_0,
        id=function_id or f"pair-function:{name}",
        artifact_version_id=_VERSION,
        name=name,
        symbol=name,
        language="c",
        source_location=source,
        binary_location=binary,
        signature=None,
        attributes=cast(JsonObject, {}),
    )


def _node(function_id: str | None, *, kind: PairNodeKind = PairNodeKind.FUNCTION) -> PairNode:
    return PairNode(
        schema_version=SchemaVersion.VALUE_1_0_0,
        id=f"pair-node:{function_id or 'external'}",
        artifact_version_id=_VERSION,
        function_id=function_id,
        kind=kind,
        location=None,
        attributes=cast(JsonObject, {}),
    )


def _call(source_node_id: str, target_node_id: str, *, edge_type: PairEdgeType) -> PairEdge:
    return PairEdge(
        schema_version=SchemaVersion.VALUE_1_0_0,
        id=f"pair-edge:{source_node_id}->{target_node_id}",
        artifact_version_id=_VERSION,
        source_node_id=source_node_id,
        target_node_id=target_node_id,
        type=edge_type,
        scope="source",
        confidence=1.0,
        evidence_id=None,
        attributes=cast(JsonObject, {}),
    )


def test_call_path_reports_the_anchor_with_its_immediate_callers_and_callees() -> None:
    anchor = _function("handler", path="src/app.c", line=10)
    caller = _function("main", path="src/main.c", line=1)
    callee = _function("parse", path="src/parse.c", line=30)
    functions = [anchor, caller, callee]
    nodes = [_node(anchor["id"]), _node(caller["id"]), _node(callee["id"])]
    edges = [
        _call(_node(caller["id"])["id"], _node(anchor["id"])["id"], edge_type=PairEdgeType.CALL),
        _call(_node(anchor["id"])["id"], _node(callee["id"])["id"], edge_type=PairEdgeType.CALL),
    ]

    steps = build_call_path_steps(functions, nodes, edges, anchor["id"])

    assert steps == [
        {
            "relation": "target",
            "function_name": "handler",
            "path": "src/app.c",
            "line": 10,
            "address": None,
        },
        {
            "relation": "caller",
            "function_name": "main",
            "path": "src/main.c",
            "line": 1,
            "address": None,
        },
        {
            "relation": "callee",
            "function_name": "parse",
            "path": "src/parse.c",
            "line": 30,
            "address": None,
        },
    ]


def test_call_path_ignores_non_call_edges_and_the_anchor_itself() -> None:
    anchor = _function("handler", path="src/app.c", line=10)
    other = _function("sink", path="src/sink.c", line=40)
    function_node = _node(anchor["id"])
    other_node = _node(other["id"])
    edges = [
        _call(function_node["id"], other_node["id"], edge_type=PairEdgeType.CONTROL_FLOW),
        _call(function_node["id"], other_node["id"], edge_type=PairEdgeType.XREF),
        # A self-loop must never be reported as its own caller or callee.
        _call(function_node["id"], function_node["id"], edge_type=PairEdgeType.CALL),
    ]

    steps = build_call_path_steps([anchor, other], [function_node, other_node], edges, anchor["id"])

    assert [step["relation"] for step in steps] == ["target"]


def test_call_path_resolves_binary_edges_through_instruction_nodes() -> None:
    """Binary call edges start at instruction nodes, not function nodes."""
    anchor = _function("win_main", address=0x401000)
    caller = _function("entry", address=0x400000)
    functions = [anchor, caller]
    anchor_function_node = _node(anchor["id"])
    caller_function_node = _node(caller["id"])
    anchor_instruction = PairNode(
        schema_version=SchemaVersion.VALUE_1_0_0,
        id="pair-node:0x401010",
        artifact_version_id=_VERSION,
        function_id=anchor["id"],
        kind="instruction",
        location=None,
        attributes=cast(JsonObject, {}),
    )
    nodes = [anchor_function_node, caller_function_node, anchor_instruction]
    edges = [
        _call(
            caller_function_node["id"],
            anchor_instruction["id"],
            edge_type=PairEdgeType.CALL,
        )
    ]

    steps = build_call_path_steps(functions, nodes, edges, anchor["id"])

    assert steps == [
        {
            "relation": "target",
            "function_name": "win_main",
            "path": None,
            "line": None,
            "address": 0x401000,
        },
        {
            "relation": "caller",
            "function_name": "entry",
            "path": None,
            "line": None,
            "address": 0x400000,
        },
    ]


def test_call_path_skips_unresolved_external_callees() -> None:
    anchor = _function("handler", path="src/app.c", line=10)
    anchor_node = _node(anchor["id"])
    # An external target has no function node, so there is nothing to name.
    external = _node(None, kind=PairNodeKind.MEMORY_OBJECT)
    edges = [_call(anchor_node["id"], external["id"], edge_type=PairEdgeType.CALL)]

    steps = build_call_path_steps([anchor], [anchor_node, external], edges, anchor["id"])

    assert [step["relation"] for step in steps] == ["target"]


def test_call_path_is_deduplicated_and_bounded() -> None:
    anchor = _function("handler", path="src/app.c", line=10)
    callees = [
        _function(f"callee_{index}", path=f"src/c{index}.c", line=index + 1) for index in range(5)
    ]
    functions = [anchor, *callees]
    nodes = [_node(anchor["id"]), *(_node(callee["id"]) for callee in callees)]
    edges = [
        _call(_node(anchor["id"])["id"], _node(callee["id"])["id"], edge_type=PairEdgeType.CALL)
        for callee in callees
    ] + [
        # A repeated call to the same callee must not add a second step.
        _call(_node(anchor["id"])["id"], _node(callees[0]["id"])["id"], edge_type=PairEdgeType.CALL)
    ]

    steps = build_call_path_steps(functions, nodes, edges, anchor["id"], max_steps=3)

    assert len(steps) == 3
    assert steps[0]["relation"] == "target"
    assert [step["function_name"] for step in steps[1:]] == ["callee_0", "callee_1"]


def test_call_path_without_a_resolved_anchor_is_empty() -> None:
    anchor = _function("handler", path="src/app.c", line=10)

    assert build_call_path_steps([anchor], [_node(anchor["id"])], [], "pair-function:absent") == []


def test_call_path_rejects_a_negative_budget() -> None:
    with pytest.raises(ValueError):
        build_call_path_steps([], [], [], "pair-function:absent", max_steps=-1)


def _source_result() -> SourceImportResult:
    def location(start: int) -> SourceLocation:
        return SourceLocation(
            artifact_version_id=_VERSION,
            path="src/main.c",
            start_line=start,
            start_column=1,
            end_line=start + 1,
            end_column=2,
        )

    return cast(
        SourceImportResult,
        {
            "schema_version": "1.0.0",
            "artifact_version_id": _VERSION,
            "files": [],
            "functions": [
                {
                    "id": "source-function:main",
                    "name": "main",
                    "qualified_name": "main",
                    "kind": "function",
                    "language": "c",
                    "parameters": [],
                    "location": location(1),
                },
                {
                    "id": "source-function:helper",
                    "name": "helper",
                    "qualified_name": "helper",
                    "kind": "function",
                    "language": "c",
                    "parameters": [],
                    "location": location(10),
                },
            ],
            "calls": [
                {
                    "caller_id": "source-function:main",
                    "callee": "helper",
                    "location": location(3),
                }
            ],
            "capability_profile": {
                "schema_version": "1.0.0",
                "artifact_version_id": _VERSION,
                "languages": ["c"],
                "architectures": [],
                "build_systems": [],
                "capabilities": [],
                "created_at": "2026-09-08T10:00:00Z",
            },
        },
    )


def test_call_path_projects_a_real_imported_pair_graph(persistence_database_url: str) -> None:
    """The builder consumes the exact shape the PAIR importer writes."""

    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        importer = SourcePairImporter(database)
        query = PairQueryService(database)
        tool = cast(
            ToolIdentity, {"name": "source-import", "version": "1.0.0", "image_digest": None}
        )
        try:
            async with database.transaction() as repositories:
                await repositories.projects.add(project("project:call-path"))
                await repositories.artifacts.add(
                    artifact(
                        "artifact:call-path",
                        project_id="project:call-path",
                        current_version_id=_VERSION,
                    )
                )
                await repositories.artifacts.add_version(
                    artifact_version(
                        "artifact-version:call-path",
                        artifact_id="artifact:call-path",
                        digest_character="c",
                    )
                )
            await importer.import_source_result(
                _source_result(),
                raw_object_ref="cas://sha256/" + "a" * 64,
                tool=tool,
                created_at="2026-09-08T10:00:00Z",
            )

            helper = (await query.functions_at_location(_VERSION, "src/main.c", 10))[0]
            neighbourhood = await query.neighborhood(_VERSION, helper["id"], depth=1)
            steps = build_call_path_steps(
                neighbourhood.functions,
                neighbourhood.nodes,
                neighbourhood.edges,
                helper["id"],
            )

            assert steps == [
                {
                    "relation": "target",
                    "function_name": "helper",
                    "path": "src/main.c",
                    "line": 10,
                    "address": None,
                },
                {
                    "relation": "caller",
                    "function_name": "main",
                    "path": "src/main.c",
                    "line": 1,
                    "address": None,
                },
            ]
        finally:
            await database.dispose()

    asyncio.run(scenario())
