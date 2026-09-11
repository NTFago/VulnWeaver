from __future__ import annotations

import asyncio
from typing import cast

from vulnweaver_contracts import (
    Artifact,
    ArtifactKind,
    ArtifactVersion,
    BinaryAnalysisResult,
    BinaryAnalysisStatus,
    BinaryArchitecture,
    BinaryFormat,
    BinarySymbolicStatus,
    BinaryXrefType,
    SchemaVersion,
    StaticToolStatus,
    ToolIdentity,
)
from vulnweaver_pair import BinaryPairImporter, PairQueryService
from vulnweaver_persistence import Database, DatabaseSettings

from tests.persistence.factories import TIMESTAMP, project


def binary_result() -> BinaryAnalysisResult:
    return BinaryAnalysisResult(
        schema_version=SchemaVersion.VALUE_1_0_0,
        artifact_version_id="artifact-version:binary-original",
        analyzed_artifact_version_id="artifact-version:binary-unpacked",
        format=BinaryFormat.ELF,
        architecture=BinaryArchitecture.X86_64,
        bits=64,
        endianness="little",
        image_base=0x400000,
        entry_point=0x401000,
        compiler="GCC",
        packer="UPX",
        packed=True,
        sections=[
            {
                "name": ".text",
                "virtual_address": 0x401000,
                "virtual_size": 0x1000,
                "file_offset": 0x200,
                "file_size": 0x1000,
                "readable": True,
                "writable": False,
                "executable": True,
            }
        ],
        functions=[
            {
                "name": "main",
                "address": 0x401000,
                "size": 0x10,
                "file_offset": 0x200,
                "attributes": {"source": "objdump"},
            },
            {
                "name": "helper",
                "address": 0x401020,
                "size": 1,
                "file_offset": None,
                "attributes": {"source": "ghidra"},
            },
        ],
        instructions=[
            {
                "address": 0x401000,
                "file_offset": 0x200,
                "bytes": "e81b000000",
                "mnemonic": "call",
                "operands": "401020 <helper>",
                "function_name": "main",
            },
            {
                "address": 0x401005,
                "file_offset": 0x205,
                "bytes": "c3",
                "mnemonic": "ret",
                "operands": "",
                "function_name": "main",
            },
            {
                "address": 0x401020,
                "file_offset": None,
                "bytes": "c3",
                "mnemonic": "ret",
                "operands": "",
                "function_name": "helper",
            },
        ],
        basic_blocks=[
            {
                "function_name": "main",
                "start_address": 0x401000,
                "end_address": 0x401005,
                "successor_addresses": [0x401005],
            },
            {
                "function_name": "main",
                "start_address": 0x401005,
                "end_address": 0x401006,
                "successor_addresses": [],
            },
            {
                "function_name": "helper",
                "start_address": 0x401020,
                "end_address": 0x401021,
                "successor_addresses": [],
            },
        ],
        xrefs=[
            {
                "source_address": 0x401000,
                "target_address": 0x401020,
                "type": BinaryXrefType.CALL,
                "source_function": "main",
                "target_symbol": "helper",
            },
            {
                "source_address": 0x401005,
                "target_address": 0x500000,
                "type": BinaryXrefType.DATA,
                "source_function": "main",
                "target_symbol": "global_value",
            },
        ],
        pseudocode=[
            {
                "function_name": "main",
                "address": 0x401000,
                "text": "int main(void) { return helper(); }",
                "tool_name": "ghidra",
            }
        ],
        symbolic_facts=[
            {
                "function_address": 0x401000,
                "status": BinarySymbolicStatus.COMPLETED,
                "steps": 4,
                "explored_states": 4,
                "reached_addresses": [0x401000, 0x401020],
                "unconstrained_states": 0,
                "reason": None,
            }
        ],
        strings=[],
        imports=[],
        tool_runs=[
            {
                "tool_name": "objdump",
                "tool_version": "2.42",
                "status": StaticToolStatus.SUCCEEDED,
                "exit_code": 0,
                "reason": None,
                "raw_output": "bounded",
            }
        ],
        status=BinaryAnalysisStatus.COMPLETE,
        created_at="2026-09-09T13:00:00Z",
    )


def test_binary_pair_import_is_idempotent_and_address_queryable(
    persistence_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        importer = BinaryPairImporter(database)
        query = PairQueryService(database)
        tool = cast(
            ToolIdentity,
            {"name": "binary-import", "version": "1.0.0", "image_digest": None},
        )
        try:
            async with database.transaction() as repositories:
                await repositories.projects.add(project("project:binary-pair"))
                await repositories.artifacts.add(
                    Artifact(
                        schema_version=SchemaVersion.VALUE_1_0_0,
                        id="artifact:binary-original",
                        project_id="project:binary-pair",
                        kind=ArtifactKind.ELF,
                        current_version_id="artifact-version:binary-original",
                        created_at=TIMESTAMP,
                    )
                )
                await repositories.artifacts.add_version(
                    ArtifactVersion(
                        schema_version=SchemaVersion.VALUE_1_0_0,
                        id="artifact-version:binary-original",
                        artifact_id="artifact:binary-original",
                        digest="sha256:" + "c" * 64,
                        object_ref="cas://sha256/" + "c" * 64,
                        generation_config={},
                        created_at=TIMESTAMP,
                    )
                )
                await repositories.artifacts.add(
                    Artifact(
                        schema_version=SchemaVersion.VALUE_1_0_0,
                        id="artifact:binary-unpacked",
                        project_id="project:binary-pair",
                        kind=ArtifactKind.DERIVED,
                        current_version_id="artifact-version:binary-unpacked",
                        created_at=TIMESTAMP,
                    )
                )
                await repositories.artifacts.add_version(
                    ArtifactVersion(
                        schema_version=SchemaVersion.VALUE_1_0_0,
                        id="artifact-version:binary-unpacked",
                        artifact_id="artifact:binary-unpacked",
                        digest="sha256:" + "d" * 64,
                        object_ref="cas://sha256/" + "d" * 64,
                        parent_version_id="artifact-version:binary-original",
                        produced_by=tool,
                        generation_config={"format": "upx-unpacked-binary"},
                        created_at=TIMESTAMP,
                    )
                )
            result = binary_result()
            first = await importer.import_binary_result(
                result,
                raw_object_ref="cas://sha256/" + "e" * 64,
                tool=tool,
                created_at="2026-09-09T13:00:00Z",
            )
            second = await importer.import_binary_result(
                result,
                raw_object_ref="cas://sha256/" + "e" * 64,
                tool=tool,
                created_at="2026-09-09T13:00:00Z",
            )
            assert first == second
            assert first.functions == 2
            assert first.nodes == 9
            assert first.edges == 3

            functions = await query.list_functions("artifact-version:binary-unpacked")
            assert [item["name"] for item in functions] == ["helper", "main"]
            main = next(item for item in functions if item["name"] == "main")
            helper = next(item for item in functions if item["name"] == "helper")
            assert main["binary_location"] is not None
            assert (
                main["binary_location"]["artifact_version_id"] == "artifact-version:binary-unpacked"
            )
            assert helper["binary_location"] is not None
            assert helper["binary_location"]["file_offset"] == 0x220
            assert main["attributes"]["pseudocode"][0]["tool_name"] == "ghidra"
            assert main["attributes"]["symbolic_fact"]["status"] == "completed"

            located = await query.functions_at_address("artifact-version:binary-unpacked", 0x401004)
            assert [item["name"] for item in located] == ["main"]
            neighborhood = await query.neighborhood(
                "artifact-version:binary-unpacked", main["id"], depth=1
            )
            assert {item["name"] for item in neighborhood.functions} == {
                "main",
                "helper",
            }
            assert {edge["scope"] for edge in neighborhood.edges} >= {
                "binary-call",
                "binary-control-flow",
            }
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_two_runs_of_one_artifact_do_not_share_function_rows(
    persistence_database_url: str,
) -> None:
    """Each analysis run owns its PAIR rows; the artifact owns none.

    Function identity includes the analyzed version, but the rows used to be
    filed under the uploaded artifact, so every new task added another copy of
    every function to the same list and the workbench showed them all.
    """

    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        importer = BinaryPairImporter(database)
        query = PairQueryService(database)
        tool = cast(
            ToolIdentity,
            {"name": "binary-import", "version": "1.0.0", "image_digest": None},
        )
        try:
            async with database.transaction() as repositories:
                await repositories.projects.add(project("project:binary-pair-runs"))
                await repositories.artifacts.add(
                    Artifact(
                        schema_version=SchemaVersion.VALUE_1_0_0,
                        id="artifact:binary-original-runs",
                        project_id="project:binary-pair-runs",
                        kind=ArtifactKind.ELF,
                        current_version_id="artifact-version:binary-original-runs",
                        created_at=TIMESTAMP,
                    )
                )
                await repositories.artifacts.add_version(
                    ArtifactVersion(
                        schema_version=SchemaVersion.VALUE_1_0_0,
                        id="artifact-version:binary-original-runs",
                        artifact_id="artifact:binary-original-runs",
                        digest="sha256:" + "c" * 64,
                        object_ref="cas://sha256/" + "c" * 64,
                        generation_config={},
                        created_at=TIMESTAMP,
                    )
                )
                # PAIR rows are foreign-keyed to the analyzed image, so each run
                # needs the version its analysis produced.
                for version_id, parent_digest in (
                    ("artifact-version:binary-unpacked-runs", "d"),
                    ("artifact-version:binary-unpacked-runs-2", "e"),
                ):
                    await repositories.artifacts.add(
                        Artifact(
                            schema_version=SchemaVersion.VALUE_1_0_0,
                            id=f"artifact:{version_id}",
                            project_id="project:binary-pair-runs",
                            kind=ArtifactKind.DERIVED,
                            current_version_id=version_id,
                            created_at=TIMESTAMP,
                        )
                    )
                    await repositories.artifacts.add_version(
                        ArtifactVersion(
                            schema_version=SchemaVersion.VALUE_1_0_0,
                            id=version_id,
                            artifact_id=f"artifact:{version_id}",
                            digest=f"sha256:{parent_digest}" + "0" * 63,
                            object_ref=f"cas://sha256:{parent_digest}" + "0" * 63,
                            parent_version_id="artifact-version:binary-original-runs",
                            produced_by=tool,
                            generation_config={"format": "upx-unpacked-binary"},
                            created_at=TIMESTAMP,
                        )
                    )
            first_run = cast(
                BinaryAnalysisResult,
                {
                    **binary_result(),
                    "analyzed_artifact_version_id": "artifact-version:binary-unpacked-runs",
                },
            )
            second_run = cast(
                BinaryAnalysisResult,
                {
                    **first_run,
                    "analyzed_artifact_version_id": "artifact-version:binary-unpacked-runs-2",
                },
            )
            await importer.import_binary_result(
                first_run,
                raw_object_ref="cas://sha256/" + "e" * 64,
                tool=tool,
                created_at="2026-09-09T13:00:00Z",
            )
            await importer.import_binary_result(
                second_run,
                raw_object_ref="cas://sha256/" + "f" * 64,
                tool=tool,
                created_at="2026-09-09T13:05:00Z",
            )
            # Each run owns its own copy, so the lists stay complete and neither
            # run can grow the other's.
            first = await query.list_functions("artifact-version:binary-unpacked-runs")
            second = await query.list_functions("artifact-version:binary-unpacked-runs-2")
            assert [item["name"] for item in first] == ["helper", "main"]
            assert [item["name"] for item in second] == ["helper", "main"]
            # The uploaded artifact holds no function rows of its own.
            assert await query.list_functions("artifact-version:binary-original-runs") == []
        finally:
            await database.dispose()

    asyncio.run(scenario())
