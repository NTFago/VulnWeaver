"""Confirmation facts must come from evidence, and only from strong evidence."""

from __future__ import annotations

import asyncio
from typing import cast
from uuid import uuid4

from vulnweaver_contracts import (
    Evidence,
    EvidenceRelation,
    EvidenceStrength,
    EvidenceType,
    Finding,
    FindingCategory,
    FindingEvidence,
    FindingStatus,
    Job,
    Review,
    Severity,
    ToolIdentity,
)
from vulnweaver_orchestrator import FindingReviewGate, ReviewJobScheduler
from vulnweaver_persistence import Database, DatabaseSettings

from tests.persistence.factories import artifact, artifact_version, job, project, task

TIMESTAMP = "2026-09-11T08:00:00Z"


def _evidence(
    evidence_id: str,
    *,
    evidence_type: EvidenceType,
    strength: EvidenceStrength,
    replay_recipe: dict[str, object],
    tool: ToolIdentity | None = None,
    artifact_ref: str = "cas://sha256/" + "c" * 64,
) -> Evidence:
    return cast(
        Evidence,
        {
            "schema_version": "1.0.0",
            "id": evidence_id,
            "type": evidence_type,
            "strength": strength,
            "artifact_ref": artifact_ref,
            "digest": "sha256:" + "c" * 64,
            "tool": tool,
            "input_ref": "cas://sha256/" + "d" * 64,
            "command_hash": None,
            "exit_code": None,
            "stdout_ref": None,
            "stderr_ref": None,
            "replay_recipe": replay_recipe,
            "created_at": TIMESTAMP,
        },
    )


def _finding(
    identifier: str, task_id: str, category: FindingCategory, version_id: str
) -> Finding:
    return cast(
        Finding,
        {
            "schema_version": "1.0.0",
            "id": identifier,
            "task_id": task_id,
            "category": category,
            "cwe_id": "CWE-787",
            "title": "out-of-bounds write",
            "severity": Severity.HIGH,
            "confidence": 0.4,
            "location": {
                "artifact_version_id": version_id,
                "path": "src/app.c",
                "start_line": 4,
                "start_column": 1,
                "end_line": 6,
                "end_column": 2,
            },
            "dataflow": [],
            "call_path": [],
            "status": FindingStatus.CANDIDATE,
            "evidence_ids": [],
            "review_ids": [],
            "poc_ids": [],
            "fix_suggestion": "bounds check",
            "created_at": TIMESTAMP,
        },
    )


def _relation(finding_id: str, evidence_id: str) -> FindingEvidence:
    return FindingEvidence(
        schema_version="1.0.0",
        finding_id=finding_id,
        evidence_id=evidence_id,
        relation=EvidenceRelation.SUPPORTS,
        weight=1.0,
        created_by="test",
        created_at=TIMESTAMP,
    )


def _review(finding_id: str) -> Review:
    return Review(
        schema_version="1.0.0",
        id=f"review:{finding_id}",
        finding_id=finding_id,
        model="review/test-model",
        outcome=FindingStatus.CONFIRMED,
        rationale="the crash reproduces on the recorded input",
        supersedes_review_id=None,
        created_at=TIMESTAMP,
    )


async def _seed(database: Database, category: FindingCategory) -> tuple[str, str]:
    suffix = uuid4().hex
    finding_id = f"finding:{suffix}"
    version_id = f"artifact-version:{suffix}"
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
            task(f"task:{suffix}", project_id=f"project:{suffix}", artifact_version_ids=[])
        )
        await repositories.findings.create(
            _finding(finding_id, f"task:{suffix}", category, version_id)
        )
    return finding_id, f"task:{suffix}"


async def _attach(database: Database, finding_id: str, evidence: Evidence) -> None:
    async with database.transaction() as repositories:
        await repositories.evidence.create(evidence)
        await repositories.findings.link_evidence(_relation(finding_id, evidence["id"]))


def test_reproduced_crash_confirms_a_memory_corruption_finding(
    persistence_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        gate = FindingReviewGate(database)
        try:
            finding_id, _ = await _seed(database, FindingCategory.MEMORY_CORRUPTION)
            await _attach(
                database,
                finding_id,
                _evidence(
                    "evidence:crash",
                    evidence_type=EvidenceType.CRASH_RECORD,
                    strength=EvidenceStrength.STRONG,
                    replay_recipe={
                        "kind": "fuzz_crash",
                        "reproducible": True,
                        "stack_hash": "stack:abc",
                        "signal": "SIGSEGV",
                    },
                    tool=ToolIdentity(name="afl-casr", version="1.0.0", image_digest=None),
                    artifact_ref="cas://sha256/" + "e" * 64,
                ),
            )
            result = await gate.submit(_review(finding_id))
            assert result.decision is not None
            assert result.decision.allowed is True, result.decision.reason_codes
            async with database.transaction() as repositories:
                stored = await repositories.findings.get(finding_id)
            assert stored["status"] is FindingStatus.CONFIRMED
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_a_model_explanation_never_establishes_confirmation_facts(
    persistence_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        gate = FindingReviewGate(database)
        try:
            finding_id, _ = await _seed(database, FindingCategory.MEMORY_CORRUPTION)
            await _attach(
                database,
                finding_id,
                _evidence(
                    "evidence:explanation",
                    evidence_type=EvidenceType.MODEL_EXPLANATION,
                    strength=EvidenceStrength.STRONG,
                    replay_recipe={
                        "kind": "semantic_model_audit",
                        "reproducible": True,
                        "controllable_input": True,
                    },
                ),
            )
            result = await gate.submit(_review(finding_id))
            assert result.persisted is False
            assert result.decision is not None
            assert "missing_strong_reproducible_evidence" in result.decision.reason_codes
            assert "missing_fact:repeatable_crash" in result.decision.reason_codes
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_a_crash_alone_does_not_confirm_an_injection_finding(
    persistence_database_url: str,
) -> None:
    """A crash proves memory corruption, not a source-to-sink path."""

    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        gate = FindingReviewGate(database)
        try:
            finding_id, _ = await _seed(database, FindingCategory.INJECTION)
            await _attach(
                database,
                finding_id,
                _evidence(
                    "evidence:crash",
                    evidence_type=EvidenceType.CRASH_RECORD,
                    strength=EvidenceStrength.STRONG,
                    replay_recipe={"kind": "fuzz_crash", "reproducible": True},
                    artifact_ref="cas://sha256/" + "e" * 64,
                ),
            )
            result = await gate.submit(_review(finding_id))
            assert result.persisted is False
            assert result.decision is not None
            assert "missing_fact:source_to_sink_path" in result.decision.reason_codes
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_a_review_revision_is_distinct_from_the_first_review(
    persistence_database_url: str,
) -> None:
    """New evidence after the first review must be able to open a new review."""

    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        scheduler = ReviewJobScheduler(database)
        finding_id = "finding:revision"
        source: Job = job("job:source:revision", task_id="task:revision")
        try:
            async with database.transaction() as repositories:
                await repositories.projects.add(project("project:revision"))
                await repositories.artifacts.add(
                    artifact(
                        "artifact:revision",
                        project_id="project:revision",
                        current_version_id="artifact-version:revision",
                    )
                )
                await repositories.artifacts.add_version(
                    artifact_version(
                        "artifact-version:revision", artifact_id="artifact:revision"
                    )
                )
                await repositories.tasks.create(
                    task(
                        "task:revision",
                        project_id="project:revision",
                        artifact_version_ids=["artifact-version:revision"],
                    )
                )
                await repositories.findings.create(
                    _finding(
                        finding_id,
                        "task:revision",
                        FindingCategory.MEMORY_CORRUPTION,
                        "artifact-version:revision",
                    )
                )

            async with database.transaction() as repositories:
                first = await scheduler.schedule_in_transaction(
                    repositories, source, [finding_id]
                )
                again = await scheduler.schedule_in_transaction(
                    repositories, source, [finding_id]
                )
                assert len(first) == 1
                assert again == ()

            async with database.transaction() as repositories:
                opened = await scheduler.schedule_in_transaction(
                    repositories, source, [finding_id], revision="evidence-abc123"
                )
                repeat = await scheduler.schedule_in_transaction(
                    repositories, source, [finding_id], revision="evidence-abc123"
                )
            assert len(opened) == 1
            assert opened != first
            assert repeat == ()

            async with database.transaction() as repositories:
                jobs = await repositories.jobs.list_for_task("task:revision")
            assert len(jobs) == 2
        finally:
            await database.dispose()

    asyncio.run(scenario())
