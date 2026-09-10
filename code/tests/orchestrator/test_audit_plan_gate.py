"""ADR-021 gate: NO_FINDINGS requires the required audit baselines to have run."""

from __future__ import annotations

import asyncio
from typing import Any, cast
from uuid import uuid4

from sqlalchemy import update
from vulnweaver_contracts import (
    Job,
    JobKind,
    JobStatus,
    TaskResult,
    TaskStatus,
    WorkerResult,
)
from vulnweaver_orchestrator import TaskAggregateSettlementHook
from vulnweaver_persistence import Database, DatabaseSettings, Repositories
from vulnweaver_persistence.models import jobs as jobs_table

from tests.persistence.factories import artifact, artifact_version, job, project, task


class NoopAuditScheduler:
    """Stands in for a configured scheduler; schedules nothing."""

    async def schedule_in_transaction(
        self, repositories: Repositories, source_job: Job
    ) -> str | None:
        return None


def _succeeded(job_id: str, task_id: str, *, kind: JobKind) -> Job:
    value = job(job_id, task_id=task_id, idempotency_key=job_id, kind=kind)
    value["status"] = JobStatus.SUCCEEDED
    return value


def _result(job_id: str) -> WorkerResult:
    return WorkerResult(
        schema_version="1.0.0",
        job_id=job_id,
        status=JobStatus.SUCCEEDED,
        produced_artifact_version_ids=[],
        evidence_ids=[],
        failure=None,
    )


async def _seed(database: Database, suffix: str, version_id: str) -> None:
    async with database.transaction() as repositories:
        await repositories.projects.add(project(f"project:{suffix}"))
        await repositories.artifacts.add(
            artifact(
                f"artifact:{suffix}",
                project_id=f"project:{suffix}",
                current_version_id=version_id,
            )
        )
        await repositories.artifacts.add_version(
            artifact_version(version_id, artifact_id=f"artifact:{suffix}")
        )
        await repositories.tasks.create(
            task(
                f"task:{suffix}",
                project_id=f"project:{suffix}",
                artifact_version_ids=[version_id],
                idempotency_key=f"task:{suffix}",
            )
        )


def test_no_findings_blocked_until_semantic_baseline_ran(
    persistence_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        suffix = uuid4().hex
        task_id = f"task:{suffix}"
        version_id = f"artifact-version:{suffix}"
        static = _succeeded(f"job:static:{suffix}", task_id, kind=JobKind.SOURCE_ANALYSIS)
        audit_job = job(
            f"job:audit:{suffix}",
            task_id=task_id,
            idempotency_key=f"audit:{suffix}",
            kind=JobKind.SEMANTIC_AUDIT,
        )
        await _seed(database, suffix, version_id)
        hook = TaskAggregateSettlementHook(None, cast(Any, NoopAuditScheduler()))
        try:
            async with database.transaction() as repositories:
                await repositories.jobs.create_without_outbox(static)
                await repositories.jobs.create_without_outbox(audit_job)
                await hook.after_terminal(repositories, static, _result(static["id"]))
                current = await repositories.tasks.get(task_id)
            # The semantic baseline is queued, not done: NO_FINDINGS is blocked.
            assert current["status"] is TaskStatus.ANALYZING
            assert current["result"] is None

            async with database.engine.begin() as connection:
                await connection.execute(
                    update(jobs_table)
                    .where(jobs_table.c.id == audit_job["id"])
                    .values(status="succeeded")
                )
            audit_job["status"] = JobStatus.SUCCEEDED
            async with database.transaction() as repositories:
                await hook.after_terminal(repositories, audit_job, _result(audit_job["id"]))
                finished = await repositories.tasks.get(task_id)
            assert finished["status"] is TaskStatus.COMPLETED
            assert finished["result"] is TaskResult.NO_FINDINGS
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_no_findings_completes_without_configured_audit_scheduler(
    persistence_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        suffix = uuid4().hex
        task_id = f"task:{suffix}"
        version_id = f"artifact-version:{suffix}"
        static = _succeeded(f"job:static:{suffix}", task_id, kind=JobKind.SOURCE_ANALYSIS)
        await _seed(database, suffix, version_id)
        try:
            async with database.transaction() as repositories:
                await repositories.jobs.create_without_outbox(static)
                hook = TaskAggregateSettlementHook(None, None)
                await hook.after_terminal(repositories, static, _result(static["id"]))
                finished = await repositories.tasks.get(task_id)
            # Degraded deployments without the semantic scheduler keep the
            # legacy fixed-pipeline behaviour.
            assert finished["status"] is TaskStatus.COMPLETED
            assert finished["result"] is TaskResult.NO_FINDINGS
        finally:
            await database.dispose()

    asyncio.run(scenario())
