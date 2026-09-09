from __future__ import annotations

import asyncio
from typing import cast
from uuid import uuid4

from sqlalchemy import update
from vulnweaver_contracts import (
    FailureKind,
    Finding,
    FindingCategory,
    FindingStatus,
    Job,
    JobKind,
    JobStatus,
    SchemaVersion,
    Severity,
    StructuredFailure,
    TaskResult,
    TaskStatus,
    WorkerResult,
)
from vulnweaver_orchestrator import ReviewJobScheduler, TaskAggregateSettlementHook
from vulnweaver_persistence import Database, DatabaseSettings
from vulnweaver_persistence.models import jobs

from tests.persistence.factories import artifact, artifact_version, job, project, task


def test_terminal_job_settlement_advances_task_through_review_and_completion(
    persistence_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        suffix = uuid4().hex
        project_id = f"project:{suffix}"
        artifact_id = f"artifact:{suffix}"
        version_id = f"artifact-version:{suffix}"
        task_id = f"task:{suffix}"
        static = job(f"job:static:{suffix}", task_id=task_id, idempotency_key=f"static:{suffix}")
        static["status"] = JobStatus.SUCCEEDED
        second_static = job(
            f"job:static-second:{suffix}",
            task_id=task_id,
            idempotency_key=f"static-second:{suffix}",
        )
        second_static["status"] = JobStatus.QUEUED
        hook = TaskAggregateSettlementHook(ReviewJobScheduler(database))
        try:
            async with database.transaction() as repositories:
                await repositories.projects.add(project(project_id))
                await repositories.artifacts.add(
                    artifact(artifact_id, project_id=project_id, current_version_id=version_id)
                )
                await repositories.artifacts.add_version(
                    artifact_version(version_id, artifact_id=artifact_id)
                )
                await repositories.tasks.create(
                    task(
                        task_id,
                        project_id=project_id,
                        artifact_version_ids=[version_id],
                        idempotency_key=f"task:{suffix}",
                    )
                )
                await repositories.jobs.create_without_outbox(static)
                await repositories.jobs.create_without_outbox(second_static)
                await repositories.findings.create(
                    _finding(f"finding:{suffix}", task_id, version_id)
                )
                await hook.after_terminal(repositories, static, _result(static))

            async with database.transaction() as repositories:
                assert (await repositories.tasks.get(task_id))["status"] is TaskStatus.ANALYZING
                assert len(await repositories.jobs.list_for_task(task_id)) == 2
            async with database.engine.begin() as connection:
                await connection.execute(
                    update(jobs).where(jobs.c.id == second_static["id"]).values(status="succeeded")
                )
            second_static["status"] = JobStatus.SUCCEEDED
            async with database.transaction() as repositories:
                await hook.after_terminal(repositories, second_static, _result(second_static))
                current_jobs = await repositories.jobs.list_for_task(task_id)
                review = next(item for item in current_jobs if item["kind"] is JobKind.REVIEW)
                assert (await repositories.tasks.get(task_id))["status"] is TaskStatus.REVIEWING

            async with database.engine.begin() as connection:
                await connection.execute(
                    update(jobs).where(jobs.c.id == review["id"]).values(status="succeeded")
                )
            review["status"] = JobStatus.SUCCEEDED
            async with database.transaction() as repositories:
                await hook.after_terminal(repositories, review, _result(review))

            async with database.transaction() as repositories:
                finished = await repositories.tasks.get(task_id)
                assert finished["status"] is TaskStatus.COMPLETED
                assert finished["result"] is TaskResult.SUCCESS
                events = await repositories.task_events.list_after(task_id)
                assert [event["payload"]["status"] for event in events] == [
                    TaskStatus.VALIDATING,
                    TaskStatus.ANALYZING,
                    TaskStatus.REVIEWING,
                    TaskStatus.COMPLETED,
                ]
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_failed_static_analysis_completes_task_as_partial_without_phantom_phases(
    persistence_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        suffix = uuid4().hex
        project_id = f"project:{suffix}"
        artifact_id = f"artifact:{suffix}"
        version_id = f"artifact-version:{suffix}"
        task_id = f"task:{suffix}"
        imported = job(
            f"job:import:{suffix}",
            task_id=task_id,
            idempotency_key=f"import:{suffix}",
            kind=JobKind.IMPORT,
        )
        imported["status"] = JobStatus.SUCCEEDED
        static = job(
            f"job:static:{suffix}",
            task_id=task_id,
            idempotency_key=f"static:{suffix}",
        )
        static["status"] = JobStatus.FAILED
        static["failure"] = _tool_failure()
        hook = TaskAggregateSettlementHook()
        try:
            async with database.transaction() as repositories:
                await repositories.projects.add(project(project_id))
                await repositories.artifacts.add(
                    artifact(artifact_id, project_id=project_id, current_version_id=version_id)
                )
                await repositories.artifacts.add_version(
                    artifact_version(version_id, artifact_id=artifact_id)
                )
                await repositories.tasks.create(
                    task(
                        task_id,
                        project_id=project_id,
                        artifact_version_ids=[version_id],
                        idempotency_key=f"task:{suffix}",
                    )
                )
                await repositories.jobs.create_without_outbox(imported)
                await repositories.jobs.create_without_outbox(static)
                await hook.after_terminal(repositories, static, _failed_result(static))

            async with database.transaction() as repositories:
                finished = await repositories.tasks.get(task_id)
                assert finished["status"] is TaskStatus.COMPLETED
                assert finished["result"] is TaskResult.PARTIAL
                events = await repositories.task_events.list_after(task_id)
                assert [event["payload"]["status"] for event in events] == [
                    TaskStatus.VALIDATING,
                    TaskStatus.ANALYZING,
                    TaskStatus.COMPLETED,
                ]
        finally:
            await database.dispose()

    asyncio.run(scenario())


def _result(value: Job) -> WorkerResult:
    return WorkerResult(
        schema_version=SchemaVersion.VALUE_1_0_0,
        job_id=str(value["id"]),
        status=JobStatus.SUCCEEDED,
        produced_artifact_version_ids=[],
        evidence_ids=[],
        failure=None,
    )


def _failed_result(value: Job) -> WorkerResult:
    return WorkerResult(
        schema_version=SchemaVersion.VALUE_1_0_0,
        job_id=str(value["id"]),
        status=JobStatus.FAILED,
        produced_artifact_version_ids=[],
        evidence_ids=[],
        failure=_tool_failure(),
    )


def _tool_failure() -> StructuredFailure:
    return StructuredFailure(
        code="static_analysis.tool_exit_nonzero",
        kind=FailureKind.TOOL,
        message="static analysis tool did not complete",
        retryable=False,
        details={"tool_name": "semgrep", "reason": "tool_exit_nonzero"},
    )


def _finding(finding_id: str, task_id: str, version_id: str) -> Finding:
    return cast(
        Finding,
        {
            "schema_version": "1.0.0",
            "id": finding_id,
            "task_id": task_id,
            "category": FindingCategory.STATIC_ONLY,
            "cwe_id": "CWE-20",
            "title": "candidate",
            "severity": Severity.MEDIUM,
            "confidence": 0.5,
            "location": {
                "artifact_version_id": version_id,
                "path": "src/app.py",
                "start_line": 1,
                "start_column": 1,
                "end_line": 1,
                "end_column": 2,
            },
            "dataflow": [],
            "status": FindingStatus.CANDIDATE,
            "evidence_ids": [],
            "review_ids": [],
            "poc_ids": [],
            "fix_suggestion": "validate input",
            "created_at": "2026-09-09T00:00:00Z",
        },
    )
