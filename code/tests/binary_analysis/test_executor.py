from __future__ import annotations

import asyncio
import io
import json
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from vulnweaver_artifact_store import LocalContentAddressedStore
from vulnweaver_binary_analysis import (
    BinaryAnalysisLimits,
    BinaryImportExecutor,
    BinaryMetadata,
    ToolContribution,
    UpxOutcome,
)
from vulnweaver_contracts import (
    Artifact,
    ArtifactKind,
    ArtifactVersion,
    BinaryBasicBlock,
    BinaryFunction,
    BinaryInstruction,
    BinaryPseudocode,
    BinarySymbolicFact,
    BinarySymbolicStatus,
    BinaryToolRun,
    BinaryXref,
    BinaryXrefType,
    Job,
    JobKind,
    JobStatus,
    Project,
    ResourceBudget,
    StaticToolStatus,
    Task,
    TaskStatus,
    validate_contract,
)
from vulnweaver_pair import BinaryPairImporter
from vulnweaver_persistence import Database, DatabaseSettings

from tests.binary_analysis.samples import elf64_sample
from tests.persistence.factories import TIMESTAMP, budget


class _UnpacksUpx:
    async def unpack(
        self,
        path: Path,
        destination: Path,
        limits: BinaryAnalysisLimits,
        cancellation: asyncio.Event,
    ) -> UpxOutcome:
        del path, limits, cancellation
        destination.write_bytes(elf64_sample())
        return UpxOutcome(
            run=BinaryToolRun(
                tool_name="upx",
                tool_version="4.2.4",
                status=StaticToolStatus.SUCCEEDED,
                exit_code=0,
                reason="unpacked",
                raw_output="Unpacked 1 file",
            ),
            packed=True,
            unpacked_path=destination,
        )


class _FailedGhidraAdapter:
    name = "ghidra"

    async def analyze(
        self,
        path: Path,
        metadata: BinaryMetadata,
        limits: BinaryAnalysisLimits,
        cancellation: asyncio.Event,
    ) -> ToolContribution:
        del path, metadata, limits, cancellation
        return ToolContribution(
            run=BinaryToolRun(
                tool_name="ghidra",
                tool_version="11.4",
                status=StaticToolStatus.FAILED,
                exit_code=1,
                reason="analysis_failed",
                raw_output="headless analysis failed",
            )
        )


class _NormalizedAdapter:
    name = "objdump"

    async def analyze(
        self,
        path: Path,
        metadata: BinaryMetadata,
        limits: BinaryAnalysisLimits,
        cancellation: asyncio.Event,
    ) -> ToolContribution:
        del path, limits, cancellation
        return ToolContribution(
            run=BinaryToolRun(
                tool_name="objdump",
                tool_version="GNU objdump 2.42",
                status=StaticToolStatus.SUCCEEDED,
                exit_code=0,
                reason=None,
                raw_output="bounded raw output",
            ),
            functions=(
                BinaryFunction(
                    name="main",
                    address=metadata.entry_point,
                    size=7,
                    file_offset=metadata.virtual_address_to_offset(metadata.entry_point),
                    attributes={"source": "test"},
                ),
            ),
            instructions=(
                BinaryInstruction(
                    address=metadata.entry_point,
                    file_offset=metadata.virtual_address_to_offset(metadata.entry_point),
                    bytes="55",
                    mnemonic="push",
                    operands="%rbp",
                    function_name="main",
                ),
            ),
            basic_blocks=(
                BinaryBasicBlock(
                    function_name="main",
                    start_address=metadata.entry_point,
                    end_address=metadata.entry_point + 1,
                    successor_addresses=[],
                ),
            ),
            xrefs=(
                BinaryXref(
                    source_address=metadata.entry_point,
                    target_address=metadata.entry_point + 16,
                    type=BinaryXrefType.CALL,
                    source_function="main",
                    target_symbol="helper",
                ),
            ),
            pseudocode=(
                BinaryPseudocode(
                    function_name="main",
                    address=metadata.entry_point,
                    text="int main(void) { return 0; }",
                    tool_name="ghidra",
                ),
            ),
            symbolic_facts=(
                BinarySymbolicFact(
                    function_address=metadata.entry_point,
                    status=BinarySymbolicStatus.COMPLETED,
                    steps=2,
                    explored_states=2,
                    reached_addresses=[metadata.entry_point],
                    unconstrained_states=0,
                    reason=None,
                ),
            ),
        )


def test_binary_executor_publishes_normalized_immutable_result_and_replays(
    persistence_database_url: str, tmp_path: Path
) -> None:
    async def scenario() -> None:
        suffix = uuid.uuid4().hex[:12]
        project_id = f"project:binary-{suffix}"
        artifact_id = f"artifact:binary-{suffix}"
        version_id = f"artifact-version:binary-{suffix}"
        task_id = f"task:binary-{suffix}"
        job_id = f"job:binary-{suffix}"
        database = Database(DatabaseSettings(persistence_database_url))
        store = LocalContentAddressedStore(tmp_path / "store")
        stored = store.put_stream(io.BytesIO(elf64_sample(upx_section=True)), max_bytes=1024 * 1024)
        project = Project(
            schema_version="1.0.0",
            id=project_id,
            name="Binary integration project",
            input_scope=["local://authorized-binary"],
            permission_mode="request_permission",
            exploit_validation_enabled=False,
            resource_budget=cast(ResourceBudget, budget()),
            created_at=TIMESTAMP,
        )
        artifact = Artifact(
            schema_version="1.0.0",
            id=artifact_id,
            project_id=project_id,
            kind=ArtifactKind.ELF,
            current_version_id=version_id,
            created_at=TIMESTAMP,
        )
        version = ArtifactVersion(
            schema_version="1.0.0",
            id=version_id,
            artifact_id=artifact_id,
            digest=stored.digest,
            object_ref=stored.object_ref,
            generation_config={},
            created_at=TIMESTAMP,
        )
        task = Task(
            schema_version="1.0.0",
            id=task_id,
            project_id=project_id,
            artifact_version_ids=[version_id],
            status=TaskStatus.CREATED,
            result=None,
            failure=None,
            idempotency_key=f"task-binary-{suffix}",
            resource_budget=cast(ResourceBudget, budget()),
            created_at=TIMESTAMP,
            updated_at=TIMESTAMP,
        )
        job = Job(
            schema_version="1.0.0",
            id=job_id,
            task_id=task_id,
            kind=JobKind.IMPORT,
            tool={
                "name": "binary-import",
                "version": "1.0.0",
                "image_digest": "sha256:" + "a" * 64,
            },
            arguments={"artifact_version_id": version_id},
            input_refs=[stored.object_ref],
            status=JobStatus.RUNNING,
            idempotency_key=f"job-binary-{suffix}",
            resource_budget=cast(ResourceBudget, budget()),
            retry_policy={
                "max_attempts": 2,
                "backoff_seconds": 1.0,
                "retryable_failure_kinds": ["environment"],
            },
            attempt=1,
            lease=None,
            failure=None,
            created_at=TIMESTAMP,
            updated_at=TIMESTAMP,
        )
        try:
            async with database.transaction() as repositories:
                await repositories.projects.add(project)
                await repositories.artifacts.add(artifact)
                await repositories.artifacts.add_version(version)
                await repositories.tasks.create(task)
            executor = BinaryImportExecutor(
                database,
                store,
                adapters=(_NormalizedAdapter(), _FailedGhidraAdapter()),
                upx=_UnpacksUpx(),
                pair_importer=BinaryPairImporter(database),
                scratch_root=tmp_path,
            )
            result = await executor.execute(job, asyncio.Event())
            assert result["status"] is JobStatus.SUCCEEDED
            assert len(result["produced_artifact_version_ids"]) == 3
            unpacked_version_id, result_version_id, readable_version_id = result[
                "produced_artifact_version_ids"
            ]
            async with database.transaction() as repositories:
                unpacked_version = await repositories.artifacts.get_version(unpacked_version_id)
                result_version = await repositories.artifacts.get_version(result_version_id)
                readable_version = await repositories.artifacts.get_version(readable_version_id)
                assert unpacked_version.get("parent_version_id") == version_id
                assert result_version.get("parent_version_id") == unpacked_version_id
                produced_by = result_version.get("produced_by")
                assert isinstance(produced_by, Mapping)
                assert produced_by.get("name") == "binary-import"
                assert readable_version.get("parent_version_id") == result_version_id
                generation_config = readable_version.get("generation_config")
                assert isinstance(generation_config, Mapping)
                assert generation_config.get("format") == "binary-readable-pseudocode"
                pair_functions = await repositories.pair.list_functions(version_id)
                assert [item["name"] for item in pair_functions] == ["main"]
                assert pair_functions[0]["binary_location"] is not None
                assert (
                    pair_functions[0]["binary_location"]["artifact_version_id"]
                    == unpacked_version_id
                )
            with store.open(result_version["object_ref"]) as stream:
                document = json.load(stream)
            validate_contract("BinaryAnalysisResult", document)
            assert document["format"] == "elf"
            assert document["architecture"] == "x86_64"
            assert document["status"] == "partial"
            assert document["packed"] is True
            assert document["packer"] == "UPX"
            assert document["analyzed_artifact_version_id"] == unpacked_version_id
            assert document["functions"][0]["name"] == "main"
            assert document["instructions"][0]["file_offset"] == 0x200
            assert document["basic_blocks"][0]["function_name"] == "main"
            assert document["xrefs"][0]["target_symbol"] == "helper"
            assert document["pseudocode"][0]["tool_name"] == "ghidra"
            assert document["symbolic_facts"][0]["status"] == "completed"
            with store.open(readable_version["object_ref"]) as stream:
                readable_document = json.load(stream)
            assert (
                readable_document["original_pseudocode_excerpts"][0]["text"]
                == "int main(void) { return 0; }"
            )
            assert (
                readable_document["recovered_pseudocode"][0]["tool_name"]
                == "vulnweaver-readable"
            )

            replay = await executor.execute(job, asyncio.Event())
            assert replay["produced_artifact_version_ids"] == [
                unpacked_version_id,
                result_version_id,
                readable_version_id,
            ]
            invalid_job = cast(
                Job,
                {
                    **job,
                    "id": f"job:binary-invalid-target-{suffix}",
                    "idempotency_key": f"job-binary-invalid-target-{suffix}",
                    "arguments": {
                        "artifact_version_id": version_id,
                        "target_addresses": [0xDEADBEEF],
                    },
                },
            )
            invalid = await executor.execute(invalid_job, asyncio.Event())
            assert invalid["status"] is JobStatus.FAILED
            assert invalid["failure"] is not None
            assert invalid["failure"]["code"] == "binary_import.target_outside_executable_section"
            assert invalid["produced_artifact_version_ids"] == []
        finally:
            await database.dispose()

    asyncio.run(scenario())
