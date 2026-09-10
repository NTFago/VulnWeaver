from __future__ import annotations

import asyncio
from typing import cast

import pytest
from vulnweaver_contracts import (
    Evidence,
    EvidenceRelation,
    EvidenceStrength,
    EvidenceType,
    Finding,
    FindingCategory,
    FindingEvidence,
    FindingStatus,
    Review,
    Severity,
    ToolIdentity,
)
from vulnweaver_persistence import Database, DatabaseSettings, PersistenceInvariantError

from tests.persistence.factories import artifact, artifact_version, project, task


def test_candidate_finding_and_evidence_link_are_idempotent(
    persistence_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        try:
            async with database.transaction() as repositories:
                await repositories.projects.add(project("project:finding"))
                await repositories.artifacts.add(
                    artifact(
                        "artifact:finding",
                        project_id="project:finding",
                        current_version_id="artifact-version:finding",
                    )
                )
                await repositories.artifacts.add_version(
                    artifact_version(
                        "artifact-version:finding",
                        artifact_id="artifact:finding",
                        digest_character="c",
                    )
                )
                await repositories.tasks.create(
                    task(
                        "task:finding",
                        project_id="project:finding",
                        artifact_version_ids=["artifact-version:finding"],
                    )
                )
                evidence = cast(
                    Evidence,
                    {
                        "schema_version": "1.0.0",
                        "id": "evidence:finding",
                        "type": EvidenceType.TOOL_OUTPUT,
                        "strength": EvidenceStrength.SUPPORTING,
                        "artifact_ref": "cas://sha256/" + "a" * 64,
                        "digest": "sha256:" + "a" * 64,
                        "tool": cast(
                            ToolIdentity,
                            {"name": "semgrep", "version": "1.0.0", "image_digest": None},
                        ),
                        "input_ref": "cas://sha256/" + "b" * 64,
                        "command_hash": None,
                        "exit_code": 0,
                        "stdout_ref": "cas://sha256/" + "c" * 64,
                        "stderr_ref": None,
                        "replay_recipe": {"kind": "static_analysis"},
                        "created_at": "2026-09-08T10:00:00Z",
                    },
                )
                await repositories.evidence.create(evidence)
                finding = cast(
                    Finding,
                    {
                        "schema_version": "1.0.0",
                        "id": "finding:candidate",
                        "task_id": "task:finding",
                        "category": FindingCategory.STATIC_ONLY,
                        "cwe_id": "CWE-95",
                        "title": "Unsafe eval",
                        "severity": Severity.HIGH,
                        "confidence": 0.7,
                        "location": {
                            "artifact_version_id": "artifact-version:finding",
                            "path": "src/app.py",
                            "start_line": 2,
                            "start_column": 1,
                            "end_line": 2,
                            "end_column": 10,
                        },
                        "dataflow": [],
                        "call_path": [
                            {
                                "relation": "target",
                                "function_name": "handler",
                                "path": "src/app.py",
                                "line": 2,
                                "address": None,
                            },
                            {
                                "relation": "caller",
                                "function_name": "main",
                                "path": "src/main.py",
                                "line": 10,
                                "address": None,
                            },
                        ],
                        "status": FindingStatus.CANDIDATE,
                        "evidence_ids": [evidence["id"]],
                        "review_ids": [],
                        "poc_ids": [],
                        "fix_suggestion": "Avoid eval on untrusted input",
                        "created_at": "2026-09-08T10:00:00Z",
                    },
                )
                assert await repositories.findings.create(finding) == finding
                assert await repositories.findings.create(finding) == finding
                relation = cast(
                    FindingEvidence,
                    {
                        "schema_version": "1.0.0",
                        "finding_id": finding["id"],
                        "evidence_id": evidence["id"],
                        "relation": EvidenceRelation.SUPPORTS,
                        "weight": 1.0,
                        "created_by": "tool:semgrep",
                        "created_at": "2026-09-08T10:00:00Z",
                    },
                )
                assert await repositories.findings.link_evidence(relation) == relation
                assert await repositories.findings.link_evidence(relation) == relation
                contextual = cast(
                    FindingEvidence,
                    {
                        **relation,
                        "relation": EvidenceRelation.CONTEXTUAL,
                        "created_at": "2026-09-08T10:00:00+00:00",
                    },
                )
                stored_contextual = await repositories.findings.link_evidence(contextual)
                assert stored_contextual["created_at"] == "2026-09-08T10:00:00Z"
                relations = await repositories.findings.list_evidence_relations(finding["id"])
                assert {item["relation"] for item in relations} == {
                    EvidenceRelation.SUPPORTS,
                    EvidenceRelation.CONTEXTUAL,
                }
                assert (await repositories.findings.get(finding["id"]))[
                    "status"
                ] is FindingStatus.CANDIDATE
                review = cast(
                    Review,
                    {
                        "schema_version": "1.0.0",
                        "id": "review:finding",
                        "finding_id": finding["id"],
                        "outcome": FindingStatus.CONFIRMED,
                        "rationale": "Independent review agrees with the evidence.",
                        "model": "review-model",
                        "supersedes_review_id": None,
                        "created_at": "2026-09-08T10:01:00Z",
                    },
                )
                with pytest.raises(PersistenceInvariantError):
                    await repositories.findings.add_review(review)
                await repositories.findings.add_review(review, confirmation_allowed=True)
                assert (await repositories.findings.get(finding["id"]))[
                    "status"
                ] is FindingStatus.CONFIRMED
                assert len(await repositories.findings.list_reviews(finding["id"])) == 1
                assert len(await repositories.findings.list_for_task("task:finding")) == 1
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_concurrent_reviews_preserve_complete_ordered_history(
    persistence_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        finding_id = "finding:concurrent-reviews"
        try:
            async with database.transaction() as repositories:
                await repositories.projects.add(project("project:concurrent-reviews"))
                await repositories.artifacts.add(
                    artifact(
                        "artifact:concurrent-reviews",
                        project_id="project:concurrent-reviews",
                        current_version_id="artifact-version:concurrent-reviews",
                    )
                )
                await repositories.artifacts.add_version(
                    artifact_version(
                        "artifact-version:concurrent-reviews",
                        artifact_id="artifact:concurrent-reviews",
                        digest_character="d",
                    )
                )
                await repositories.tasks.create(
                    task(
                        "task:concurrent-reviews",
                        project_id="project:concurrent-reviews",
                        artifact_version_ids=["artifact-version:concurrent-reviews"],
                    )
                )
                await repositories.findings.create(
                    cast(
                        Finding,
                        {
                            "schema_version": "1.0.0",
                            "id": finding_id,
                            "task_id": "task:concurrent-reviews",
                            "category": FindingCategory.STATIC_ONLY,
                            "cwe_id": "CWE-20",
                            "title": "Concurrent review target",
                            "severity": Severity.MEDIUM,
                            "confidence": 0.5,
                            "location": {
                                "artifact_version_id": "artifact-version:concurrent-reviews",
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
                            "fix_suggestion": "Validate input",
                            "created_at": "2026-09-08T10:00:00Z",
                        },
                    )
                )

            reviews = [
                cast(
                    Review,
                    {
                        "schema_version": "1.0.0",
                        "id": f"review:concurrent-{index}",
                        "finding_id": finding_id,
                        "outcome": outcome,
                        "rationale": f"review {index}",
                        "model": "review-model",
                        "supersedes_review_id": None,
                        "created_at": f"2026-09-08T10:0{index}:00+00:00",
                    },
                )
                for index, outcome in (
                    (1, FindingStatus.FALSE_POSITIVE),
                    (2, FindingStatus.CANDIDATE),
                )
            ]

            async def add_review(review: Review) -> None:
                async with database.transaction() as repositories:
                    await repositories.findings.add_review(review)

            await asyncio.gather(*(add_review(review) for review in reversed(reviews)))

            async with database.transaction() as repositories:
                stored = await repositories.findings.get(finding_id)
                assert stored["review_ids"] == [review["id"] for review in reviews]
                assert stored["status"] is FindingStatus.CANDIDATE
                stored_reviews = await repositories.findings.list_reviews(finding_id)
                assert [review["id"] for review in stored_reviews] == [
                    review["id"] for review in reviews
                ]
        finally:
            await database.dispose()

    asyncio.run(scenario())
