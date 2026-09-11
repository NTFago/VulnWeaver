from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any, cast
from uuid import uuid4

from sqlalchemy import update
from vulnweaver_artifact_store import LocalContentAddressedStore
from vulnweaver_contracts import (
    AgentRun,
    Job,
    JobKind,
    JobStatus,
    PairFunction,
    RunStatus,
    SourceLocation,
    WorkerResult,
)
from vulnweaver_model_gateway import ModelCallResult
from vulnweaver_orchestrator import (
    SemanticAuditJobExecutor,
    SemanticAuditor,
    SemanticAuditScheduler,
    TaskAggregateSettlementHook,
)
from vulnweaver_orchestrator.source_facts import SourceReviewFacts
from vulnweaver_persistence import Database, DatabaseSettings
from vulnweaver_persistence.models import jobs as jobs_table
from vulnweaver_source_analysis import SourceExcerpt

from tests.persistence.factories import artifact, artifact_version, job, project, task

NOW = datetime(2026, 9, 10, 8, 0, tzinfo=UTC)
TIMESTAMP = "2026-09-10T08:00:00Z"


class FakeAuditModel:
    def __init__(self, output: dict[str, object] | None, failure=None) -> None:
        self._output = output
        self._failure = failure
        self.messages: list[list[dict[str, str]]] = []

    async def complete_structured(self, **kwargs: object) -> ModelCallResult:
        self.messages.append(cast(list[dict[str, str]], kwargs["messages"]))
        run = cast(
            AgentRun,
            {
                "schema_version": "1.0.0",
                "id": "agent-run:stub",
                "task_id": "task:stub",
                "status": RunStatus.FAILED if self._failure else RunStatus.SUCCEEDED,
                "model": "audit/test-model",
                "prompt_hash": "sha256:" + "a" * 64,
                "input_refs": [],
                "decisions": [],
                "token_usage": {"input_tokens": 10, "output_tokens": 10},
                "failure": self._failure,
                "created_at": TIMESTAMP,
                "updated_at": TIMESTAMP,
            },
        )
        return ModelCallResult(self._output, run, self._failure, "endpoint-1")


class StubFactLoader:
    async def load(self, task_id: str, location: dict) -> SourceReviewFacts:
        excerpt = SourceExcerpt(
            artifact_version_id=str(location["artifact_version_id"]),
            archive_ref="cas://sha256/" + "b" * 64,
            archive_digest="sha256:" + "b" * 64,
            path=str(location["path"]),
            file_digest="sha256:" + "c" * 64,
            start_line=int(location["start_line"]),
            end_line=int(location["end_line"]),
            text="def handle(request):\n    return eval(request)\n",
            truncated=False,
        )
        return SourceReviewFacts(True, None, excerpt)


def report(findings: list[dict[str, object]]) -> dict[str, object]:
    return {"schema_version": "1.0.0", "summary": "audited", "findings": findings}


def model_finding(path: str, start_line: int) -> dict[str, object]:
    return {
        "cwe_id": "CWE-95",
        "title": "eval on request data",
        "severity": "high",
        "path": path,
        "start_line": start_line,
        "rationale": "request-controlled expression evaluation",
    }


def pair_function(identifier: str, version_id: str, path: str) -> PairFunction:
    return PairFunction(
        schema_version="1.0.0",
        id=identifier,
        artifact_version_id=version_id,
        name="handle",
        symbol="handle",
        language="python",
        source_location=SourceLocation(
            artifact_version_id=version_id,
            path=path,
            start_line=1,
            start_column=1,
            end_line=2,
            end_column=30,
        ),
        binary_location=None,
        signature="def handle(request)",
        attributes={},
    )


async def seed(database: Database) -> tuple[str, str]:
    suffix = uuid4().hex
    async with database.transaction() as repositories:
        await repositories.projects.add(project(f"project:{suffix}"))
        await repositories.artifacts.add(
            artifact(
                f"artifact:{suffix}",
                project_id=f"project:{suffix}",
                current_version_id=f"artifact-version:{suffix}",
            )
        )
        await repositories.artifacts.add_version(
            artifact_version(f"artifact-version:{suffix}", artifact_id=f"artifact:{suffix}")
        )
        await repositories.tasks.create(
            task(
                f"task:{suffix}",
                project_id=f"project:{suffix}",
                artifact_version_ids=[f"artifact-version:{suffix}"],
            )
        )
    return suffix, f"artifact-version:{suffix}"


def semantic_job(identifier: str, task_id: str) -> Job:
    value = job(
        identifier, task_id=task_id, idempotency_key=identifier, kind=JobKind.SEMANTIC_AUDIT
    )
    return value


def test_semantic_audit_scheduler_is_idempotent(persistence_database_url: str) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        suffix, _ = await seed(database)
        source_job = job(f"job:source:{suffix}", task_id=f"task:{suffix}")
        scheduler = SemanticAuditScheduler(database)
        try:
            first = await scheduler.schedule(source_job)
            again = await scheduler.schedule(source_job)
            assert first is not None
            assert again is None
            async with database.transaction() as repositories:
                jobs = await repositories.jobs.list_for_task(f"task:{suffix}")
            assert [item["kind"] for item in jobs] == [JobKind.SEMANTIC_AUDIT]
            assert jobs[0]["status"] is JobStatus.QUEUED
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_executor_projects_verified_findings_and_drops_hallucinations(
    persistence_database_url: str, tmp_path: object
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        suffix, version_id = await seed(database)
        task_id = f"task:{suffix}"
        real_path = "src/app.py"
        async with database.transaction() as repositories:
            await repositories.pair.import_graph(
                [pair_function(f"pair-fn:{suffix}", version_id, real_path)],
                [],
                [],
                None,
                created_at=NOW,
            )
        model = FakeAuditModel(
            report(
                [
                    model_finding(real_path, 2),
                    model_finding("elsewhere/ghost.py", 7),
                ]
            )
        )
        auditor = SemanticAuditor(
            database,
            model,
            store=LocalContentAddressedStore(tmp_path),
            fact_loader=StubFactLoader(),
        )
        executor = SemanticAuditJobExecutor(database, auditor)
        audit_job = semantic_job(f"job:audit:{suffix}", task_id)
        try:
            result = await executor.execute(audit_job, asyncio.Event())
            assert result["status"] is JobStatus.SUCCEEDED
            assert len(result["evidence_ids"]) == 1
            async with database.transaction() as repositories:
                findings = await repositories.findings.list_for_task(task_id)
                runs = await repositories.agent_runs.list_for_task(task_id)
            assert len(findings) == 1
            assert findings[0]["cwe_id"] == "CWE-95"
            assert findings[0]["status"] == "candidate"
            assert findings[0]["location"]["path"] == real_path
            assert len(runs) == 1 and runs[0]["status"] == "succeeded"
            # The hallucinated location was dropped, never persisted.
            user_payload = model.messages[0][1]["content"]
            assert real_path in user_payload
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_executor_fails_structurally_without_model(persistence_database_url: str) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        suffix, _ = await seed(database)
        executor = SemanticAuditJobExecutor(database, None)
        audit_job = semantic_job(f"job:audit:{suffix}", f"task:{suffix}")
        try:
            result = await executor.execute(audit_job, asyncio.Event())
            assert result["status"] is JobStatus.FAILED
            assert result["failure"] is not None
            assert result["failure"]["code"] == "semantic_audit.model_unconfigured"
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_hook_schedules_audit_before_review(persistence_database_url: str) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        suffix = uuid4().hex
        task_id = f"task:{suffix}"
        version_id = f"artifact-version:{suffix}"
        source_job = job(
            f"job:source:{suffix}",
            task_id=task_id,
            idempotency_key=f"source:{suffix}",
        )
        source_job["status"] = JobStatus.SUCCEEDED
        audit_scheduler = SemanticAuditScheduler(database)
        review_scheduler = ReviewJobSchedulerStub()
        hook = TaskAggregateSettlementHook(review_scheduler, audit_scheduler)
        try:
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
                        task_id,
                        project_id=f"project:{suffix}",
                        artifact_version_ids=[version_id],
                        idempotency_key=f"task:{suffix}",
                    )
                )
                await repositories.jobs.create_without_outbox(source_job)
                await hook.after_terminal(
                    repositories, source_job, _succeeded_result(source_job["id"])
                )
                jobs = await repositories.jobs.list_for_task(task_id)
            kinds = sorted(item["kind"] for item in jobs)
            assert "semantic_audit" in kinds
            # Review is not scheduled while the audit baseline is still queued.
            assert review_scheduler.calls == []

            async with database.transaction() as repositories:
                audit_jobs = [
                    item
                    for item in await repositories.jobs.list_for_task(task_id)
                    if item["kind"] is JobKind.SEMANTIC_AUDIT
                ]
            assert len(audit_jobs) == 1
            async with database.engine.begin() as connection:
                await connection.execute(
                    update(jobs_table)
                    .where(jobs_table.c.id == audit_jobs[0]["id"])
                    .values(status="succeeded")
                )
            audit_jobs[0]["status"] = JobStatus.SUCCEEDED
            async with database.transaction() as repositories:
                await hook.after_terminal(
                    repositories, audit_jobs[0], _succeeded_result(audit_jobs[0]["id"])
                )
                assert len(review_scheduler.calls) == 1
        finally:
            await database.dispose()

    asyncio.run(scenario())


class ReviewJobSchedulerStub:
    def __init__(self) -> None:
        self.calls: list[tuple[object, list[str]]] = []

    async def schedule_in_transaction(self, repositories, source_job, finding_ids):
        self.calls.append((source_job["id"], list(finding_ids)))
        return ()


def _succeeded_result(job_id: str) -> WorkerResult:
    return WorkerResult(
        schema_version="1.0.0",
        job_id=job_id,
        status=JobStatus.SUCCEEDED,
        produced_artifact_version_ids=[],
        evidence_ids=[],
        failure=None,
    )


async def _seed_binary(database: Database, suffix: str) -> tuple[str, str, str]:
    project_id = f"project:{suffix}"
    version_id = f"artifact-version:{suffix}"
    task_id = f"task:{suffix}"
    artifact_id = f"artifact:{suffix}"
    async with database.transaction() as repositories:
        await repositories.projects.add(project(project_id))
        version = artifact_version(version_id, artifact_id=artifact_id)
        version["digest"] = "sha256:" + "f" * 64
        version["object_ref"] = "cas://sha256/" + "f" * 64
        artifact_row = dict(
            artifact(f"artifact:{suffix}", project_id=project_id, current_version_id=version_id)
        )
        artifact_row["kind"] = "elf"
        await repositories.artifacts.add(cast(Any, artifact_row))
        await repositories.artifacts.add_version(version)
        await repositories.tasks.create(
            task(
                task_id,
                project_id=project_id,
                artifact_version_ids=[version_id],
                idempotency_key=f"task-key:{suffix}",
            )
        )
    return task_id, version_id, artifact_id


def test_binary_pseudocode_finding_is_anchored_by_address(
    persistence_database_url: str, tmp_path: object
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        suffix = uuid4().hex
        task_id, version_id, artifact_id = await _seed_binary(database, suffix)
        address = 0x401000
        async with database.transaction() as repositories:
            function = pair_function(f"pair-fn:{suffix}", version_id, "src/unused.py")
            function["source_location"] = None
            function["binary_location"] = {
                "artifact_version_id": version_id,
                "image_base": 0x400000,
                "virtual_address": address,
                "file_offset": 0x1000,
                "instruction_end": address + 16,
            }
            function["attributes"] = {
                "pseudocode": "int handle(void) { char buf[8]; gets(buf); }"
            }
            await repositories.pair.import_graph([function], [], [], None, created_at=NOW)
        model = FakeAuditModel(
            {
                "schema_version": "1.0.0",
                "summary": "binary audit",
                "findings": [
                    {
                        "cwe_id": "CWE-120",
                        "title": "unchecked buffer copy",
                        "severity": "high",
                        "address": address,
                        "rationale": "gets into stack buffer",
                    },
                    {
                        "cwe_id": "CWE-476",
                        "title": "ghost dereference",
                        "severity": "medium",
                        "address": 0x999999,
                        "rationale": "hallucinated",
                    },
                ],
            }
        )
        generator = SemanticAuditor(
            database, model, LocalContentAddressedStore(cast(Any, tmp_path))
        )
        executor = SemanticAuditJobExecutor(database, generator)
        audit_job = semantic_job(f"job:audit:{suffix}", task_id)
        try:
            result = await executor.execute(audit_job, asyncio.Event())
            assert result["status"] is JobStatus.SUCCEEDED, result["failure"]
            async with database.transaction() as repositories:
                findings = await repositories.findings.list_for_task(task_id)
            assert len(findings) == 1
            assert findings[0]["cwe_id"] == "CWE-120"
            location = findings[0]["location"]
            assert location["virtual_address"] == address
            user_payload = model.messages[0][1]["content"]
            assert "gets into stack buffer" not in user_payload
            assert "handle" in user_payload
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_executor_drops_a_candidate_whose_derived_id_collides(
    persistence_database_url: str, tmp_path: object
) -> None:
    """Two candidates at the same location and CWE derive the same finding id.

    The store refuses to merge them -- they are genuinely different findings --
    and that refusal used to escape as an unhandled EntityConflict and take the
    whole audit job down.  The colliding candidate is dropped and counted.
    """

    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        suffix, version_id = await seed(database)
        task_id = f"task:{suffix}"
        real_path = "src/app.py"
        async with database.transaction() as repositories:
            await repositories.pair.import_graph(
                [pair_function(f"pair-fn:{suffix}", version_id, real_path)],
                [],
                [],
                None,
                created_at=NOW,
            )
        first = model_finding(real_path, 2)
        second = {**model_finding(real_path, 2), "title": "a different claim at the same line"}
        model = FakeAuditModel(report([first, second]))
        auditor = SemanticAuditor(
            database,
            model,
            store=LocalContentAddressedStore(tmp_path),
            fact_loader=StubFactLoader(),
        )
        executor = SemanticAuditJobExecutor(database, auditor)
        audit_job = semantic_job(f"job:audit:{suffix}", task_id)
        try:
            result = await executor.execute(audit_job, asyncio.Event())
            assert result["status"] is JobStatus.SUCCEEDED
            async with database.transaction() as repositories:
                findings = await repositories.findings.list_for_task(task_id)
            # Only the first candidate persists; the colliding one is dropped
            # rather than aborting the audit.
            assert len(findings) == 1
            assert findings[0]["title"] == "eval on request data"
        finally:
            await database.dispose()

    asyncio.run(scenario())
