from __future__ import annotations

import asyncio
from typing import cast

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
from vulnweaver_orchestrator import FindingReviewGate
from vulnweaver_persistence import Database, DatabaseSettings

from tests.persistence.factories import artifact, artifact_version, project, task


def test_review_gate_uses_isolated_facts_and_requires_strong_evidence(
    persistence_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        gate = FindingReviewGate(database)
        finding_id = "finding:review-gate"
        try:
            async with database.transaction() as repositories:
                await repositories.projects.add(project("project:review-gate"))
                await repositories.artifacts.add(
                    artifact(
                        "artifact:review-gate",
                        project_id="project:review-gate",
                        current_version_id="artifact-version:review-gate",
                    )
                )
                await repositories.artifacts.add_version(
                    artifact_version(
                        "artifact-version:review-gate",
                        artifact_id="artifact:review-gate",
                        digest_character="a",
                    )
                )
                await repositories.tasks.create(
                    task(
                        "task:review-gate",
                        project_id="project:review-gate",
                        artifact_version_ids=["artifact-version:review-gate"],
                    )
                )
                tool_evidence = _evidence(
                    "evidence:review-tool",
                    evidence_type=EvidenceType.TOOL_OUTPUT,
                    strength=EvidenceStrength.SUPPORTING,
                    replay_recipe={
                        "kind": "static_analysis_diagnostic",
                        "diagnostic_selector": {
                            "rule_id": "rule:test",
                            "location": {"path": "src/app.py", "start_line": 2},
                        },
                        "pair_snapshot": {"node_ids": ["pair-node:1"]},
                        "reproducible": False,
                        "reasoning": "untrusted static-agent narrative",
                    },
                    tool=cast(
                        ToolIdentity,
                        {
                            "name": "semgrep",
                            "version": "1.0.0",
                            "image_digest": "sha256:" + "b" * 64,
                        },
                    ),
                )
                await repositories.evidence.create(tool_evidence)
                finding = _finding(finding_id, [tool_evidence["id"]])
                await repositories.findings.create(finding)
                await repositories.findings.link_evidence(
                    _relation(finding_id, tool_evidence["id"])
                )

            context = await gate.build_fact_context(finding_id)
            assert context.cwe_id == "CWE-95"
            assert context.evidence[0].replay_facts == {
                "kind": "static_analysis_diagnostic",
                "diagnostic_selector": {
                    "rule_id": "rule:test",
                    "location": {"path": "src/app.py", "start_line": 2},
                },
                "pair_snapshot": {"node_ids": ["pair-node:1"]},
                "reproducible": False,
            }

            review = _review(finding_id)
            denied = await gate.submit(review)
            assert denied.persisted is False
            assert denied.decision is not None
            assert denied.decision.reason_codes == ("missing_strong_reproducible_evidence",)
            async with database.transaction() as repositories:
                assert await repositories.findings.list_reviews(finding_id) == []

                reproduction = _evidence(
                    "evidence:review-reproduction",
                    evidence_type=EvidenceType.REPRODUCTION_RESULT,
                    strength=EvidenceStrength.STRONG,
                    replay_recipe={"kind": "reproduction", "reproducible": True},
                    tool=None,
                )
                await repositories.evidence.create(reproduction)
                await repositories.findings.link_evidence(
                    _relation(finding_id, reproduction["id"])
                )

            accepted = await gate.submit(review)
            assert accepted.persisted is True
            assert accepted.decision is not None and accepted.decision.allowed is True
            async with database.transaction() as repositories:
                stored = await repositories.findings.get(finding_id)
                assert stored["status"] is FindingStatus.CONFIRMED
                assert len(await repositories.findings.list_reviews(finding_id)) == 1
        finally:
            await database.dispose()

    asyncio.run(scenario())


def _evidence(
    evidence_id: str,
    *,
    evidence_type: EvidenceType,
    strength: EvidenceStrength,
    replay_recipe: dict[str, object],
    tool: ToolIdentity | None,
) -> Evidence:
    return cast(
        Evidence,
        {
            "schema_version": "1.0.0",
            "id": evidence_id,
            "type": evidence_type,
            "strength": strength,
            "artifact_ref": "cas://sha256/" + "c" * 64,
            "digest": "sha256:" + "c" * 64,
            "tool": tool,
            "input_ref": "cas://sha256/" + "d" * 64,
            "command_hash": None,
            "exit_code": 0,
            "stdout_ref": None,
            "stderr_ref": None,
            "replay_recipe": replay_recipe,
            "created_at": "2026-09-09T00:00:00Z",
        },
    )


def _finding(finding_id: str, evidence_ids: list[str]) -> Finding:
    return cast(
        Finding,
        {
            "schema_version": "1.0.0",
            "id": finding_id,
            "task_id": "task:review-gate",
            "category": FindingCategory.STATIC_ONLY,
            "cwe_id": "CWE-95",
            "title": "Static analysis candidate for CWE-95",
            "severity": Severity.HIGH,
            "confidence": 0.6,
            "location": {
                "artifact_version_id": "artifact-version:review-gate",
                "path": "src/app.py",
                "start_line": 2,
                "start_column": 1,
                "end_line": 2,
                "end_column": 8,
            },
            "dataflow": [],
            "call_path": [],
            "status": FindingStatus.CANDIDATE,
            "evidence_ids": evidence_ids,
            "review_ids": [],
            "poc_ids": [],
            "fix_suggestion": "Avoid dynamic evaluation.",
            "created_at": "2026-09-09T00:00:00Z",
        },
    )


def _relation(finding_id: str, evidence_id: str) -> FindingEvidence:
    return cast(
        FindingEvidence,
        {
            "schema_version": "1.0.0",
            "finding_id": finding_id,
            "evidence_id": evidence_id,
            "relation": EvidenceRelation.SUPPORTS,
            "weight": 1.0,
            "created_by": "review-test",
            "created_at": "2026-09-09T00:00:00Z",
        },
    )


def _review(finding_id: str) -> Review:
    return cast(
        Review,
        {
            "schema_version": "1.0.0",
            "id": "review:review-gate",
            "finding_id": finding_id,
            "outcome": FindingStatus.CONFIRMED,
            "rationale": "Independent review agrees with the reproducible evidence.",
            "model": "review-model",
            "supersedes_review_id": None,
            "created_at": "2026-09-09T00:01:00Z",
        },
    )
