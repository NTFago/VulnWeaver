"""DeletionRepository regressions for self-referencing RESTRICT chains.

Pipelines mint parent and child rows (artifact versions, reviews, annotations)
inside one transaction, so rows of one chain can share a single `created_at`
(31 such pairs exist in the deployed stack). Timestamps therefore carry no
topological meaning; these tests pin deletion of chains whose timestamps do
not encode the parent-child order.
"""

from __future__ import annotations

import asyncio
from typing import cast

import pytest
from vulnweaver_contracts import (
    Annotation,
    AnnotationTargetKind,
    ArtifactVersion,
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
    Task,
    TaskResult,
    TaskStatus,
    ToolIdentity,
)
from vulnweaver_persistence import (
    Database,
    DatabaseSettings,
    EntityNotFound,
)

from tests.persistence.factories import artifact, artifact_version, project, task

# The superseded/root rows carry the LATER timestamp: a delete order derived
# from `created_at DESC` then provably touches the parent before its child,
# independent of how the database breaks timestamp ties.
LATE_TIMESTAMP = "2026-09-09T09:10:00Z"
EARLY_TIMESTAMP = "2026-09-09T09:00:00Z"


def version_row(
    identifier: str,
    *,
    artifact_id: str,
    digest_character: str,
    parent_version_id: str | None,
    created_at: str,
) -> ArtifactVersion:
    return cast(
        ArtifactVersion,
        {
            **artifact_version(
                identifier,
                artifact_id=artifact_id,
                digest_character=digest_character,
            ),
            "created_at": created_at,
            "parent_version_id": parent_version_id,
        },
    )


def completed_task(identifier: str, *, project_id: str, version_ids: list[str]) -> Task:
    return cast(
        Task,
        {
            **task(identifier, project_id=project_id, artifact_version_ids=version_ids),
            "status": TaskStatus.COMPLETED,
            "result": TaskResult.SUCCESS,
        },
    )


def evidence_row(identifier: str) -> Evidence:
    return cast(
        Evidence,
        {
            "schema_version": "1.0.0",
            "id": identifier,
            "type": EvidenceType.TOOL_OUTPUT,
            "strength": EvidenceStrength.SUPPORTING,
            "artifact_ref": "cas://sha256/" + "d" * 64,
            "digest": "sha256:" + "d" * 64,
            "tool": cast(
                ToolIdentity, {"name": "semgrep", "version": "1.0.0", "image_digest": None}
            ),
            "input_ref": "cas://sha256/" + "e" * 64,
            "command_hash": None,
            "exit_code": 0,
            "stdout_ref": "cas://sha256/" + "f" * 64,
            "stderr_ref": None,
            "replay_recipe": {"kind": "static_analysis"},
            "created_at": EARLY_TIMESTAMP,
        },
    )


def finding_row(identifier: str, *, task_id: str, version_id: str, evidence_id: str) -> Finding:
    return cast(
        Finding,
        {
            "schema_version": "1.0.0",
            "id": identifier,
            "task_id": task_id,
            "category": FindingCategory.STATIC_ONLY,
            "cwe_id": "CWE-95",
            "title": "Unsafe eval",
            "severity": Severity.HIGH,
            "confidence": 0.7,
            "location": {
                "artifact_version_id": version_id,
                "path": "src/app.py",
                "start_line": 2,
                "start_column": 1,
                "end_line": 2,
                "end_column": 10,
            },
            "dataflow": [],
            "call_path": [],
            "status": FindingStatus.CANDIDATE,
            "evidence_ids": [evidence_id],
            "review_ids": [],
            "poc_ids": [],
            "fix_suggestion": "Avoid eval on untrusted input",
            "created_at": LATE_TIMESTAMP,
        },
    )


def review_row(
    identifier: str,
    *,
    finding_id: str,
    supersedes_review_id: str | None,
    created_at: str,
) -> Review:
    return cast(
        Review,
        {
            "schema_version": "1.0.0",
            "id": identifier,
            "finding_id": finding_id,
            "outcome": FindingStatus.CANDIDATE,
            "rationale": "Review history entry.",
            "model": "review-model",
            "supersedes_review_id": supersedes_review_id,
            "created_at": created_at,
        },
    )


def annotation_row(
    identifier: str,
    *,
    task_id: str,
    finding_id: str,
    supersedes_annotation_id: str | None,
    created_at: str,
) -> Annotation:
    return cast(
        Annotation,
        {
            "schema_version": "1.0.0",
            "id": identifier,
            "task_id": task_id,
            "target_kind": AnnotationTargetKind.FINDING,
            "target_id": finding_id,
            "labels": ["triage"],
            "note": "Annotation history entry.",
            "severity_override": None,
            "author_id": "account:reviewer",
            "supersedes_annotation_id": supersedes_annotation_id,
            "created_at": created_at,
        },
    )


async def _seed_task_with_finding(database_url: str, suffix: str) -> None:
    database = Database(DatabaseSettings(database_url))
    try:
        async with database.transaction() as repositories:
            project_id = f"project:del-{suffix}"
            artifact_id = f"artifact:del-{suffix}"
            version_id = f"artifact-version:del-{suffix}"
            task_id = f"task:del-{suffix}"
            evidence_id = f"evidence:del-{suffix}"
            finding_id = f"finding:del-{suffix}"
            await repositories.projects.add(project(project_id))
            await repositories.artifacts.add(
                artifact(artifact_id, project_id=project_id, current_version_id=version_id)
            )
            await repositories.artifacts.add_version(
                version_row(
                    version_id,
                    artifact_id=artifact_id,
                    digest_character="1",
                    parent_version_id=None,
                    created_at=EARLY_TIMESTAMP,
                )
            )
            await repositories.tasks.create(
                completed_task(task_id, project_id=project_id, version_ids=[version_id])
            )
            await repositories.evidence.create(evidence_row(evidence_id))
            await repositories.findings.create(
                finding_row(
                    finding_id, task_id=task_id, version_id=version_id, evidence_id=evidence_id
                )
            )
            await repositories.findings.link_evidence(
                cast(
                    FindingEvidence,
                    {
                        "schema_version": "1.0.0",
                        "finding_id": finding_id,
                        "evidence_id": evidence_id,
                        "relation": EvidenceRelation.SUPPORTS,
                        "weight": 1.0,
                        "created_by": "tool:semgrep",
                        "created_at": LATE_TIMESTAMP,
                    },
                )
            )
    finally:
        await database.dispose()


def test_delete_project_with_non_topological_version_timestamps(
    persistence_database_url: str,
) -> None:
    """mid/leaf share one transaction timestamp while their root is younger;
    timestamp-ordered deletion would remove the root before its children."""

    async def scenario() -> None:
        chain = [
            ("root", "1", None, LATE_TIMESTAMP),
            ("mid", "2", "artifact-version:del-versions-root", EARLY_TIMESTAMP),
            ("leaf", "3", "artifact-version:del-versions-mid", EARLY_TIMESTAMP),
        ]
        database = Database(DatabaseSettings(persistence_database_url))
        try:
            async with database.transaction() as repositories:
                await repositories.projects.add(project("project:del-versions"))
                await repositories.artifacts.add(
                    artifact(
                        "artifact:del-versions",
                        project_id="project:del-versions",
                        current_version_id="artifact-version:del-versions-root",
                    )
                )
                # Insert parent-first like the production pipelines do.
                for suffix, digest_character, parent, created_at in chain:
                    await repositories.artifacts.add_version(
                        version_row(
                            f"artifact-version:del-versions-{suffix}",
                            artifact_id="artifact:del-versions",
                            digest_character=digest_character,
                            parent_version_id=parent,
                            created_at=created_at,
                        )
                    )
                await repositories.tasks.create(
                    completed_task(
                        "task:del-versions",
                        project_id="project:del-versions",
                        version_ids=[
                            f"artifact-version:del-versions-{suffix}" for suffix, *_ in chain
                        ],
                    )
                )
            async with database.transaction() as repositories:
                await repositories.deletion.delete_project("project:del-versions")
            async with database.transaction() as repositories:
                with pytest.raises(EntityNotFound):
                    await repositories.projects.get("project:del-versions")
                with pytest.raises(EntityNotFound):
                    await repositories.artifacts.get("artifact:del-versions")
                for suffix, *_ in chain:
                    with pytest.raises(EntityNotFound):
                        await repositories.artifacts.get_version(
                            f"artifact-version:del-versions-{suffix}"
                        )
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_delete_project_with_backdated_superseding_review(
    persistence_database_url: str,
) -> None:
    async def scenario() -> None:
        await _seed_task_with_finding(persistence_database_url, "reviews")
        database = Database(DatabaseSettings(persistence_database_url))
        try:
            async with database.transaction() as repositories:
                superseded = review_row(
                    "review:del-reviews-a",
                    finding_id="finding:del-reviews",
                    supersedes_review_id=None,
                    created_at=LATE_TIMESTAMP,
                )
                superseding = review_row(
                    "review:del-reviews-b",
                    finding_id="finding:del-reviews",
                    supersedes_review_id=superseded["id"],
                    created_at=EARLY_TIMESTAMP,
                )
                await repositories.findings.add_review(superseded)
                await repositories.findings.add_review(superseding)
            async with database.transaction() as repositories:
                await repositories.deletion.delete_project("project:del-reviews")
            async with database.transaction() as repositories:
                with pytest.raises(EntityNotFound):
                    await repositories.findings.get("finding:del-reviews")
                for review_id in ("review:del-reviews-a", "review:del-reviews-b"):
                    with pytest.raises(EntityNotFound):
                        await repositories.findings.get_review(review_id)
                # Evidence is task-independent: with no surviving finding the
                # orphaned evidence row must go too.
                with pytest.raises(EntityNotFound):
                    await repositories.evidence.get("evidence:del-reviews")
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_delete_project_with_backdated_superseding_annotation(
    persistence_database_url: str,
) -> None:
    async def scenario() -> None:
        await _seed_task_with_finding(persistence_database_url, "annotations")
        database = Database(DatabaseSettings(persistence_database_url))
        try:
            async with database.transaction() as repositories:
                superseded = annotation_row(
                    "annotation:del-annotations-a",
                    task_id="task:del-annotations",
                    finding_id="finding:del-annotations",
                    supersedes_annotation_id=None,
                    created_at=LATE_TIMESTAMP,
                )
                superseding = annotation_row(
                    "annotation:del-annotations-b",
                    task_id="task:del-annotations",
                    finding_id="finding:del-annotations",
                    supersedes_annotation_id=superseded["id"],
                    created_at=EARLY_TIMESTAMP,
                )
                await repositories.annotations.create(superseded)
                await repositories.annotations.create(superseding)
            async with database.transaction() as repositories:
                await repositories.deletion.delete_project("project:del-annotations")
            async with database.transaction() as repositories:
                for annotation_id in (
                    "annotation:del-annotations-a",
                    "annotation:del-annotations-b",
                ):
                    with pytest.raises(EntityNotFound):
                        await repositories.annotations.get(annotation_id)
        finally:
            await database.dispose()

    asyncio.run(scenario())
