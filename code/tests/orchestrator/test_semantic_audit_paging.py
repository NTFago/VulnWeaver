"""CR-06: the fallback audit is paged and resumable, never truncated.

The old implementation stuffed the first 256 indexed functions into one model
call and silently dropped the rest. These tests pin the replacement: every
indexed function is audited across bounded pages, each page is checkpointed
before the next model call, and a deadline stop resumes instead of restarting.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import cast
from uuid import uuid4

from vulnweaver_artifact_store import LocalContentAddressedStore
from vulnweaver_contracts import (
    AgentRun,
    JobStatus,
    PairFunction,
    RunStatus,
    SourceLocation,
)
from vulnweaver_model_gateway import ModelCallResult
from vulnweaver_orchestrator import SemanticAuditJobExecutor, SemanticAuditor
from vulnweaver_orchestrator.checkpoints import InMemoryCheckpointStore
from vulnweaver_persistence import Database, DatabaseSettings

from tests.orchestrator.test_semantic_audit import (
    TIMESTAMP,
    StubFactLoader,
    model_finding,
    semantic_job,
)
from tests.persistence.factories import artifact, artifact_version, project, task

NOW = datetime(2026, 9, 10, 8, 0, tzinfo=UTC)


class PageScriptedModel:
    """One scripted output per page index; records every page payload."""

    def __init__(self, outputs: list[dict[str, object]]) -> None:
        self._outputs = outputs
        self.pages: list[list[str]] = []

    async def complete_structured(self, **kwargs: object) -> ModelCallResult:
        messages = cast(list[dict[str, str]], kwargs["messages"])
        payload = json.loads(messages[1]["content"])
        page_index = int(payload["page"]["index"])
        self.pages.append(
            [str(item["name"]) for item in payload["functions"] if isinstance(item, dict)]
        )
        run = cast(
            AgentRun,
            {
                "schema_version": "1.0.0",
                "id": "agent-run:stub",
                "task_id": "task:stub",
                "status": RunStatus.SUCCEEDED,
                "model": "audit/test-model",
                "prompt_hash": "sha256:" + "a" * 64,
                "input_refs": [],
                "decisions": [],
                "token_usage": {"input_tokens": 10, "output_tokens": 10},
                "failure": None,
                "created_at": TIMESTAMP,
                "updated_at": TIMESTAMP,
            },
        )
        output = self._outputs[page_index] if page_index < len(self._outputs) else report_none()
        return ModelCallResult(output, run, None, "endpoint-1")


def report_none() -> dict[str, object]:
    return {"schema_version": "1.0.0", "summary": "clean", "findings": []}


def page_finding(function_name: str, path: str) -> dict[str, object]:
    return model_finding(path, 2) | {"title": f"issue in {function_name}"}


async def seed_functions(database: Database, count: int) -> tuple[str, str, list[str]]:
    """A task whose PAIR index holds `count` functions with distinct paths."""

    suffix = uuid4().hex
    version_id = f"artifact-version:{suffix}"
    names = [f"fn_{index:02d}" for index in range(count)]
    functions = [
        PairFunction(
            schema_version="1.0.0",
            id=f"pair-fn:{suffix}:{name}",
            artifact_version_id=version_id,
            name=name,
            symbol=name,
            language="python",
            source_location=SourceLocation(
                artifact_version_id=version_id,
                path=f"src/{name}.py",
                start_line=1,
                start_column=1,
                end_line=3,
                end_column=30,
            ),
            binary_location=None,
            signature=f"def {name}()",
            attributes={},
        )
        for name in names
    ]
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
        await repositories.pair.import_graph(functions, [], [], None, created_at=NOW)
        await repositories.tasks.create(
            task(
                f"task:{suffix}",
                project_id=f"project:{suffix}",
                artifact_version_ids=[version_id],
            )
        )
    return f"task:{suffix}", version_id, names


def test_paged_fallback_audits_every_function_across_pages(
    persistence_database_url: str, tmp_path: object
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        task_id, _version_id, names = await seed_functions(database, 5)
        # Page size 2 -> three pages for five functions.
        outputs = [
            report_none(),
            report_none(),
            report_none(),
        ]
        model = PageScriptedModel(outputs)
        checkpoints = InMemoryCheckpointStore()
        auditor = SemanticAuditor(
            database,
            model,
            store=LocalContentAddressedStore(tmp_path),
            fact_loader=StubFactLoader(),
            checkpoint_store=checkpoints,
            fallback_page_size=2,
        )
        executor = SemanticAuditJobExecutor(database, auditor)
        audit_job = semantic_job(f"job:audit:{uuid4().hex}", task_id)
        try:
            result = await executor.execute(audit_job, asyncio.Event())
            assert result["status"] is JobStatus.SUCCEEDED
            # No truncation: all five functions were audited across three pages.
            assert len(model.pages) == 3
            seen = [name for page in model.pages for name in page]
            assert sorted(seen) == sorted(names)
            async with database.transaction() as repositories:
                runs = await repositories.agent_runs.list_for_task(task_id)
            assert runs[0]["status"] == "succeeded"
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_paged_fallback_projects_findings_from_every_page(
    persistence_database_url: str, tmp_path: object
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        task_id, version_id, names = await seed_functions(database, 4)
        # One finding per page, anchored to that page's first function.
        outputs = [
            {
                "schema_version": "1.0.0",
                "summary": "page 0",
                "findings": [page_finding(names[0], f"src/{names[0]}.py")],
            },
            {
                "schema_version": "1.0.0",
                "summary": "page 1",
                "findings": [page_finding(names[2], f"src/{names[2]}.py")],
            },
        ]
        model = PageScriptedModel(outputs)
        auditor = SemanticAuditor(
            database,
            model,
            store=LocalContentAddressedStore(tmp_path),
            fact_loader=StubFactLoader(),
            fallback_page_size=2,
        )
        executor = SemanticAuditJobExecutor(database, auditor)
        audit_job = semantic_job(f"job:audit:{uuid4().hex}", task_id)
        try:
            result = await executor.execute(audit_job, asyncio.Event())
            assert result["status"] is JobStatus.SUCCEEDED
            assert len(result["evidence_ids"]) == 2
            async with database.transaction() as repositories:
                findings = await repositories.findings.list_for_task(task_id)
            assert {finding["title"] for finding in findings} == {
                f"issue in {names[0]}",
                f"issue in {names[2]}",
            }
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_paged_fallback_resumes_after_deadline_stop(
    persistence_database_url: str, tmp_path: object
) -> None:
    class DeadlineAfterFirstPage:
        """Clock that exceeds the deadline right after the first page.

        Call 1 initializes the attempt clock, call 2 is the first page's
        deadline check, and call 3 (before page 1) reports an expired clock.
        """

        def __init__(self) -> None:
            self.calls = 0

        def __call__(self) -> float:
            self.calls += 1
            return 0.0 if self.calls <= 2 else 100.0

    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        task_id, _version_id, names = await seed_functions(database, 4)
        model = PageScriptedModel([])
        checkpoints = InMemoryCheckpointStore()
        first = SemanticAuditor(
            database,
            model,
            store=LocalContentAddressedStore(tmp_path),
            fact_loader=StubFactLoader(),
            checkpoint_store=checkpoints,
            fallback_page_size=2,
            fallback_deadline_seconds=50.0,
            monotonic=DeadlineAfterFirstPage(),
        )
        executor = SemanticAuditJobExecutor(database, first)
        audit_job = semantic_job(f"job:audit:{uuid4().hex}", task_id)
        try:
            stopped = await executor.execute(audit_job, asyncio.Event())
            assert stopped["status"] is JobStatus.FAILED
            assert stopped["failure"]["code"] == "semantic_audit.fallback_deadline"
            # Only the first page ran before the deadline stop.
            assert len(model.pages) == 1

            resumed_model = PageScriptedModel([])
            second = SemanticAuditor(
                database,
                resumed_model,
                store=LocalContentAddressedStore(tmp_path),
                fact_loader=StubFactLoader(),
                checkpoint_store=checkpoints,
                fallback_page_size=2,
            )
            resumed = await SemanticAuditJobExecutor(database, second).execute(
                audit_job, asyncio.Event()
            )
            assert resumed["status"] is JobStatus.SUCCEEDED
            # The second attempt audited only the remaining functions.
            resumed_names = [name for page in resumed_model.pages for name in page]
            assert sorted(resumed_names) == sorted(names[2:])
        finally:
            await database.dispose()

    asyncio.run(scenario())
