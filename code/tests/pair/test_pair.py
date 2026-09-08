from __future__ import annotations

import asyncio
from typing import cast

from vulnweaver_contracts import SourceImportResult, ToolIdentity
from vulnweaver_pair import PairQueryService, SourcePairImporter
from vulnweaver_persistence import Database, DatabaseSettings

from tests.persistence.factories import artifact, artifact_version, project


def source_result() -> SourceImportResult:
    return cast(
        SourceImportResult,
        {
            "schema_version": "1.0.0",
            "artifact_version_id": "artifact-version:pair",
            "files": [],
            "functions": [
                {
                    "id": "source-function:main",
                    "name": "main",
                    "qualified_name": "main",
                    "kind": "function",
                    "language": "c",
                    "parameters": [],
                    "location": {
                        "artifact_version_id": "artifact-version:pair",
                        "path": "src/main.c",
                        "start_line": 1,
                        "start_column": 1,
                        "end_line": 3,
                        "end_column": 2,
                    },
                },
                {
                    "id": "source-function:helper",
                    "name": "helper",
                    "qualified_name": "helper",
                    "kind": "function",
                    "language": "c",
                    "parameters": [],
                    "location": {
                        "artifact_version_id": "artifact-version:pair",
                        "path": "src/main.c",
                        "start_line": 5,
                        "start_column": 1,
                        "end_line": 7,
                        "end_column": 2,
                    },
                },
            ],
            "calls": [
                {
                    "caller_id": "source-function:main",
                    "callee": "helper",
                    "location": {
                        "artifact_version_id": "artifact-version:pair",
                        "path": "src/main.c",
                        "start_line": 2,
                        "start_column": 5,
                        "end_line": 2,
                        "end_column": 11,
                    },
                },
                {
                    "caller_id": "source-function:main",
                    "callee": "helper",
                    "location": {
                        "artifact_version_id": "artifact-version:pair",
                        "path": "src/main.c",
                        "start_line": 3,
                        "start_column": 5,
                        "end_line": 3,
                        "end_column": 11,
                    },
                },
            ],
            "capability_profile": {
                "schema_version": "1.0.0",
                "artifact_version_id": "artifact-version:pair",
                "languages": ["c"],
                "architectures": [],
                "build_systems": [],
                "capabilities": [],
                "created_at": "2026-09-08T10:00:00Z",
            },
        },
    )


def test_source_pair_import_is_idempotent_and_queryable(
    persistence_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        importer = SourcePairImporter(database)
        query = PairQueryService(database)
        tool = cast(
            ToolIdentity,
            {"name": "source-import", "version": "1.0.0", "image_digest": None},
        )
        try:
            async with database.transaction() as repositories:
                await repositories.projects.add(project("project:pair"))
                await repositories.artifacts.add(
                    artifact(
                        "artifact:pair",
                        project_id="project:pair",
                        current_version_id="artifact-version:pair",
                    )
                )
                await repositories.artifacts.add_version(
                    artifact_version(
                        "artifact-version:pair",
                        artifact_id="artifact:pair",
                        digest_character="b",
                    )
                )
            result = source_result()
            first = await importer.import_source_result(
                result,
                raw_object_ref="cas://sha256/" + "a" * 64,
                tool=tool,
                created_at="2026-09-08T10:00:00Z",
            )
            second = await importer.import_source_result(
                result,
                raw_object_ref="cas://sha256/" + "a" * 64,
                tool=tool,
                created_at="2026-09-08T10:00:00Z",
            )
            assert first == second
            assert first.functions == 2
            assert first.nodes == 2
            assert first.edges == 1

            functions = await query.list_functions("artifact-version:pair")
            assert [function["name"] for function in functions] == ["helper", "main"]
            located = await query.functions_at_location("artifact-version:pair", "src/main.c", 2)
            assert [function["name"] for function in located] == ["main"]
            main = next(function for function in functions if function["name"] == "main")
            neighborhood = await query.neighborhood("artifact-version:pair", main["id"], depth=1)
            assert {function["name"] for function in neighborhood.functions} == {"main", "helper"}
            assert len(neighborhood.edges) == 1
            assert len(neighborhood.edges[0]["attributes"]["call_sites"]) == 2
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_ambiguous_bare_call_resolves_only_with_caller_scope() -> None:
    from vulnweaver_pair.importer import _call_edges, _functions_and_nodes

    result = source_result()
    base_location = {
        "artifact_version_id": "artifact-version:pair",
        "start_line": 1,
        "start_column": 1,
        "end_line": 2,
        "end_column": 1,
    }
    result["functions"] = [
        {
            "id": "source-function:a-foo",
            "name": "foo",
            "qualified_name": "A.foo",
            "kind": "method",
            "language": "java",
            "parameters": [],
            "location": {**base_location, "path": "src/A.java"},
        },
        {
            "id": "source-function:b-foo",
            "name": "foo",
            "qualified_name": "B.foo",
            "kind": "method",
            "language": "java",
            "parameters": [],
            "location": {**base_location, "path": "src/B.java"},
        },
        {
            "id": "source-function:b-run",
            "name": "run",
            "qualified_name": "B.run",
            "kind": "method",
            "language": "java",
            "parameters": [],
            "location": {**base_location, "path": "src/B.java"},
        },
    ]
    result["calls"] = [
        {
            "caller_id": "source-function:b-run",
            "callee": "foo",
            "location": {**base_location, "path": "src/B.java"},
        }
    ]

    _functions, _nodes, source_to_node = _functions_and_nodes(result, "pair-raw:test")
    edges = _call_edges(result, source_to_node, "pair-raw:test")

    assert len(edges) == 1
    assert edges[0]["target_node_id"] == source_to_node["source-function:b-foo"]
