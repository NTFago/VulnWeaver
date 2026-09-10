"""Executor-level integration of the model planning hook (T27)."""

from __future__ import annotations

import asyncio
import io
import uuid
from pathlib import Path
from typing import cast

from vulnweaver_artifact_store import LocalContentAddressedStore
from vulnweaver_binary_analysis import (
    AngrAdapter,
    BinaryAnalysisLimits,
    BinaryImportExecutor,
    ToolContribution,
    UpxOutcome,
)
from vulnweaver_contracts import (
    Artifact,
    ArtifactKind,
    ArtifactVersion,
    BinaryToolRun,
    Job,
    JobKind,
    JobStatus,
    Project,
    ResourceBudget,
    StaticToolStatus,
    Task,
    TaskStatus,
)
from vulnweaver_persistence import Database, DatabaseSettings

from tests.binary_analysis.samples import elf64_sample
from tests.persistence.factories import TIMESTAMP, budget


class _NotPacked:
    async def unpack(
        self,
        path: Path,
        destination: Path,
        limits: BinaryAnalysisLimits,
        cancellation: asyncio.Event,
    ) -> UpxOutcome:
        del path, destination, limits, cancellation
        return UpxOutcome(
            run=BinaryToolRun(
                tool_name="upx",
                tool_version="4.2.2",
                status=StaticToolStatus.SUCCEEDED,
                exit_code=2,
                reason="not packed",
                raw_output=None,
            ),
            unpacked_path=None,
            packed=False,
        )


class _StubAngrAdapter(AngrAdapter):
    def __init__(self) -> None:
        super().__init__(enabled=True)
        self.calls: list[tuple[int, ...]] = []

    async def analyze_targets(
        self,
        path: object,
        metadata: object,
        limits: BinaryAnalysisLimits,
        cancellation: asyncio.Event,
        target_addresses: tuple[int, ...],
    ) -> ToolContribution:
        del path, metadata, limits, cancellation
        self.calls.append(tuple(target_addresses))
        return ToolContribution(
            run=BinaryToolRun(
                tool_name="angr",
                tool_version="9.2",
                status=StaticToolStatus.SUCCEEDED,
                exit_code=0,
                reason=None,
                raw_output=None,
            ),
            symbolic_facts=(
                {
                    "function_address": target_addresses[0],
                    "status": "completed",
                    "steps": 1,
                    "explored_states": 1,
                    "reached_addresses": [target_addresses[0]],
                    "unconstrained_states": 0,
                    "reason": None,
                },
            ),
        )


class _PlanningHook:
    def __init__(self, targets: tuple[int, ...]) -> None:
        self.targets = targets
        self.facts: dict[str, object] | None = None
        self.runner_targets: list[tuple[int, ...]] = []

    async def plan(self, job: object, facts: object, run_angr: object) -> tuple[int, ...]:
        del job
        self.facts = cast(dict[str, object], facts)

        async def run_angr_wrapper(targets: tuple[int, ...]) -> dict[str, object]:
            self.runner_targets.append(targets)
            return await run_angr(targets)

        await run_angr_wrapper(self.targets)
        return self.targets


def test_planning_hook_receives_facts_and_targets_reach_generation_config(
    persistence_database_url: str, tmp_path: Path
) -> None:
    async def scenario() -> None:
        suffix = uuid.uuid4().hex[:12]
        project_id = f"project:bp-{suffix}"
        artifact_id = f"artifact:bp-{suffix}"
        version_id = f"artifact-version:bp-{suffix}"
        task_id = f"task:bp-{suffix}"
        database = Database(DatabaseSettings(persistence_database_url))
        store = LocalContentAddressedStore(tmp_path / "store")
        stored = store.put_stream(io.BytesIO(elf64_sample()), max_bytes=1024 * 1024)
        entry = 0x401000
        angr = _StubAngrAdapter()
        hook = _PlanningHook(targets=(entry,))
        try:
            async with database.transaction() as repositories:
                await repositories.projects.add(
                    Project(
                        schema_version="1.0.0",
                        id=project_id,
                        name="Binary planning project",
                        input_scope=["local://authorized-binary"],
                        permission_mode="request_permission",
                        exploit_validation_enabled=False,
                        resource_budget=cast(ResourceBudget, budget()),
                        created_at=TIMESTAMP,
                    )
                )
                await repositories.artifacts.add(
                    Artifact(
                        schema_version="1.0.0",
                        id=artifact_id,
                        project_id=project_id,
                        kind=ArtifactKind.ELF,
                        current_version_id=version_id,
                        created_at=TIMESTAMP,
                    )
                )
                await repositories.artifacts.add_version(
                    ArtifactVersion(
                        schema_version="1.0.0",
                        id=version_id,
                        artifact_id=artifact_id,
                        digest=stored.digest,
                        object_ref=stored.object_ref,
                        generation_config={},
                        created_at=TIMESTAMP,
                    )
                )
                await repositories.tasks.create(
                    Task(
                        schema_version="1.0.0",
                        id=task_id,
                        project_id=project_id,
                        artifact_version_ids=[version_id],
                        status=TaskStatus.CREATED,
                        result=None,
                        idempotency_key=f"task-bp-{suffix}",
                        resource_budget=cast(ResourceBudget, budget()),
                        created_at=TIMESTAMP,
                        updated_at=TIMESTAMP,
                    )
                )
            executor = BinaryImportExecutor(
                database,
                store,
                adapters=(angr,),
                upx=_NotPacked(),
                scratch_root=tmp_path,
                planning_hook=hook,
            )
            job = Job(
                schema_version="1.0.0",
                id=f"job:bp-{suffix}",
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
                idempotency_key=f"job-bp-{suffix}",
                resource_budget=cast(ResourceBudget, budget()),
                retry_policy={
                    "max_attempts": 1,
                    "backoff_seconds": 1,
                    "retryable_failure_kinds": [],
                },
                attempt=0,
                lease=None,
                failure=None,
                created_at=TIMESTAMP,
                updated_at=TIMESTAMP,
            )
            result = await executor.execute(job, asyncio.Event())
            assert result["status"] is JobStatus.SUCCEEDED, result["failure"]
            # The hook received bounded, service-owned facts.
            assert hook.facts is not None
            assert hook.facts["packed"] is False
            assert hook.facts["input_artifact_version_id"] == version_id
            assert hook.runner_targets == [(entry,)]
            # angr ran through the hook runner with the planned targets.
            assert angr.calls == [(entry,)]
            async with database.transaction() as repositories:
                jobs = await repositories.jobs.list_for_task(task_id)
            del jobs
            with store.open(stored.object_ref) as stream:
                del stream
            result_version_id = next(
                item for item in result["produced_artifact_version_ids"]
            )
            async with database.transaction() as repositories:
                version = await repositories.artifacts.get_version(result_version_id)
            assert version["generation_config"]["target_addresses"] == [entry]
        finally:
            await database.dispose()

    asyncio.run(scenario())
