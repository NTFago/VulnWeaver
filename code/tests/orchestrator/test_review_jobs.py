from __future__ import annotations

import asyncio
from typing import cast
from uuid import uuid4

from vulnweaver_contracts import (
    AgentRun,
    Finding,
    FindingCategory,
    FindingStatus,
    JobKind,
    JobStatus,
    RunStatus,
    Severity,
)
from vulnweaver_orchestrator import ModelReviewResult, ReviewJobExecutor, ReviewJobScheduler
from vulnweaver_persistence import Database, DatabaseSettings

from tests.persistence.factories import artifact, artifact_version, job, project, task


class FakeReviewer:
    finding_id: str | None = None
    attempt_key: str | None = None
    max_output_tokens: int | None = None

    async def review(
        self,
        finding_id: str,
        *,
        attempt_key: str,
        max_output_tokens: int | None = None,
    ) -> ModelReviewResult:
        self.finding_id = finding_id
        self.attempt_key = attempt_key
        self.max_output_tokens = max_output_tokens
        return ModelReviewResult(
            cast(
                AgentRun,
                {
                    "schema_version": "1.0.0",
                    "id": "agent-run:test",
                    "task_id": "task:test",
                    "status": RunStatus.SUCCEEDED,
                    "model": "review/test",
                    "prompt_hash": "sha256:" + "a" * 64,
                    "input_refs": [],
                    "decisions": [],
                    "token_usage": {"input_tokens": 1, "output_tokens": 1},
                    "failure": None,
                    "created_at": "2026-09-09T00:00:00Z",
                    "updated_at": "2026-09-09T00:00:00Z",
                },
            ),
            None,
            "evidence:review-test",
        )


def test_review_scheduler_is_idempotent_and_inherits_task_model_budget(
    persistence_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        suffix = uuid4().hex
        project_id = f"project:{suffix}"
        artifact_id = f"artifact:{suffix}"
        version_id = f"artifact-version:{suffix}"
        task_id = f"task:{suffix}"
        finding_id = f"finding:{suffix}"
        source_job = job(
            f"job:source:{suffix}",
            task_id=task_id,
            idempotency_key=f"source:{suffix}",
        )
        try:
            async with database.transaction() as repositories:
                await repositories.projects.add(project(project_id))
                await repositories.artifacts.add(
                    artifact(
                        artifact_id,
                        project_id=project_id,
                        current_version_id=version_id,
                    )
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
                await repositories.findings.create(_finding(finding_id, task_id, version_id))

            scheduler = ReviewJobScheduler(database)
            first = await scheduler.schedule(source_job, [finding_id, finding_id])
            replay = await scheduler.schedule(source_job, [finding_id])

            assert len(first) == 1
            assert replay == ()
            async with database.transaction() as repositories:
                review_job = await repositories.jobs.get(first[0])
                assert review_job["kind"] is JobKind.REVIEW
                assert review_job.get("arguments") == {"finding_id": finding_id}
                assert review_job["resource_budget"]["max_model_tokens"] == 1000
                events = [
                    item.event
                    for item in await repositories.outbox.pending()
                    if item.event["aggregate_id"] == review_job["id"]
                ]
                assert len(events) == 1
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_review_executor_enforces_budget_and_attempt_identity() -> None:
    async def scenario() -> None:
        reviewer = FakeReviewer()
        value = job("job:review", task_id="task:test", kind=JobKind.REVIEW)
        value["arguments"] = {"finding_id": "finding:test"}
        value["attempt"] = 2
        result = await ReviewJobExecutor(reviewer).execute(value, asyncio.Event())
        assert result["status"] is JobStatus.SUCCEEDED
        assert result["evidence_ids"] == ["evidence:review-test"]
        assert reviewer.finding_id == "finding:test"
        assert reviewer.attempt_key == "job:review:attempt:2"
        assert reviewer.max_output_tokens == 1000

        value["resource_budget"]["max_model_tokens"] = 0
        denied = await ReviewJobExecutor(reviewer).execute(value, asyncio.Event())
        assert denied["status"] is JobStatus.FAILED
        assert denied["failure"] is not None
        assert denied["failure"]["code"] == "review.model_budget_exhausted"

    asyncio.run(scenario())


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
            "call_path": [],
            "status": FindingStatus.CANDIDATE,
            "evidence_ids": [],
            "review_ids": [],
            "poc_ids": [],
            "fix_suggestion": "validate input",
            "created_at": "2026-09-09T00:00:00Z",
        },
    )
