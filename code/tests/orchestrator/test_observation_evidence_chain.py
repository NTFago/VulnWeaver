"""Typed verification observations must drive confirmation through real DB rows.

Covers the ADR-036 CR-04 chain: a trusted ``verification_observation`` evidence
row (as written by the proof executor) flows through the whitelist into the
fact context, derives the memory-corruption fact set, and satisfies the
FindingPolicy only for independently verified triggers. Old-protocol PoC rows
with ``exploitable`` stay readable but establish nothing.
"""

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
    PermissionMode,
    Poc,
    PocKind,
    PocResult,
    PocStatus,
    Review,
    Severity,
    ToolIdentity,
)
from vulnweaver_orchestrator import FindingReviewGate
from vulnweaver_persistence import Database, DatabaseSettings

from tests.persistence.factories import (
    artifact,
    artifact_version,
    budget,
    project,
    task,
)

TIMESTAMP = "2026-10-03T08:00:00Z"


def _observation_payload(
    verdict: str,
    *,
    reproducible_runs: bool = True,
    target_binding: dict[str, str] | None = None,
) -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "id": "observation:" + "a" * 32,
        "kind": "proof_of_concept",
        "finding_id": "finding:placeholder",
        "verdict": verdict,
        "verdict_reasons": ["target_crash_attributed", "control_input_clean",
                            "replay_stable"],
        "driver_digest": "sha256:" + "c" * 64,
        "target_binding": target_binding or {
            "artifact_id": "artifact:sample",
            "version_id": "artifact-version:sample",
            "artifact_kind": "source_archive",
            "digest": "sha256:" + "d" * 64,
        },
        "inputs": [{"name": "inputs/0000", "digest": "sha256:" + "e" * 64,
                    "size_bytes": 50000}],
        "controls": [{"name": "controls/0000", "digest": "sha256:" + "f" * 64,
                      "size_bytes": 7}],
        "runs": [
            {
                "role": "control",
                "input_name": "0000",
                "exit_code": 0,
                "signal": None,
                "duration_millis": 3,
                "target_frames": False,
                "timed_out": False,
            },
            {
                "role": "trigger",
                "input_name": "0000",
                "exit_code": 1,
                "signal": None,
                "duration_millis": 8,
                "target_frames": True,
                "timed_out": False,
            },
        ],
        "trigger_runs": 3 if reproducible_runs else 1,
        "replay_runs": 2,
        "untrusted_claims": None,
        "verifier": ToolIdentity(
            name="proof-entrypoint", version="2.0.0", image_digest=None
        ),
        "created_at": TIMESTAMP,
    }


def _observation_evidence(
    evidence_id: str,
    finding_id: str,
    verdict: str,
    *,
    reproducible: bool = True,
    target_binding: dict[str, str] | None = None,
) -> Evidence:
    observation = _observation_payload(
        verdict, reproducible_runs=reproducible, target_binding=target_binding
    )
    observation["finding_id"] = finding_id
    return cast(
        Evidence,
        {
            "schema_version": "1.0.0",
            "id": evidence_id,
            "type": EvidenceType.VERIFICATION_OBSERVATION,
            "strength": EvidenceStrength.STRONG,
            "artifact_ref": "cas://sha256/" + "b" * 64,
            "digest": "sha256:" + "b" * 64,
            "tool": ToolIdentity(
                name="proof-entrypoint", version="2.0.0", image_digest=None
            ),
            "input_ref": "cas://sha256/" + "b" * 64,
            "command_hash": "sha256:" + "c" * 64,
            "exit_code": 1,
            "stdout_ref": None,
            "stderr_ref": None,
            "replay_recipe": {
                "kind": "verification_observation",
                "reproducible": reproducible,
                "observation": observation,
            },
            "created_at": TIMESTAMP,
        },
    )


async def _seed_finding(
    database: Database, category: FindingCategory
) -> tuple[str, dict[str, str]]:
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
            task(
                f"task:{suffix}",
                project_id=f"project:{suffix}",
                artifact_version_ids=[version_id],
                idempotency_key=f"task-key:{suffix}",
            )
        )
        await repositories.findings.create(
            cast(
                Finding,
                {
                    "schema_version": "1.0.0",
                    "id": finding_id,
                    "task_id": f"task:{suffix}",
                    "category": category,
                    "cwe_id": "CWE-674",
                    "title": "unbounded recursion in parser",
                    "severity": Severity.HIGH,
                    "confidence": 0.5,
                    "location": {
                        "artifact_version_id": version_id,
                        "path": "nested_config_parser.py",
                        "start_line": 20,
                        "start_column": 1,
                        "end_line": 20,
                        "end_column": 40,
                    },
                    "dataflow": [],
                    "call_path": [],
                    "status": FindingStatus.CANDIDATE,
                    "evidence_ids": [],
                    "review_ids": [],
                    "poc_ids": [],
                    "fix_suggestion": "bound recursion depth",
                    "created_at": TIMESTAMP,
                },
            )
        )
    return finding_id, {
        "artifact_id": f"artifact:{suffix}",
        "version_id": version_id,
        "artifact_kind": "source_archive",
        "digest": "sha256:" + "a" * 64,
    }


async def _attach(database: Database, finding_id: str, evidence: Evidence) -> None:
    async with database.transaction() as repositories:
        await repositories.evidence.create(evidence)
        await repositories.findings.link_evidence(
            FindingEvidence(
                schema_version="1.0.0",
                finding_id=finding_id,
                evidence_id=evidence["id"],
                relation=EvidenceRelation.SUPPORTS,
                weight=1.0,
                created_by="vulnweaver-proof-verifier",
                created_at=TIMESTAMP,
            )
        )


def _review(finding_id: str) -> Review:
    return Review(
        schema_version="1.0.0",
        id=f"review:{finding_id}:{uuid4().hex[:8]}",
        finding_id=finding_id,
        model="review/test-model",
        outcome=FindingStatus.CONFIRMED,
        rationale="the original target crashed through the driver on every replay",
        supersedes_review_id=None,
        created_at=TIMESTAMP,
    )


def test_verified_trigger_observation_confirms_memory_corruption(
    persistence_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        gate = FindingReviewGate(database)
        try:
            finding_id, target_binding = await _seed_finding(
                database, FindingCategory.MEMORY_CORRUPTION
            )
            await _attach(
                database,
                finding_id,
                _observation_evidence(
                    "evidence:obs-verified", finding_id, "verified_trigger",
                    target_binding=target_binding,
                ),
            )
            result = await gate.submit(_review(finding_id))
            assert result.decision is not None
            assert result.decision.allowed is True, result.decision.reason_codes
            assert result.persisted is True
            async with database.transaction() as repositories:
                stored = await repositories.findings.get(finding_id)
            assert stored["status"] is FindingStatus.CONFIRMED
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_rejected_observation_does_not_confirm(
    persistence_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        gate = FindingReviewGate(database)
        try:
            finding_id, target_binding = await _seed_finding(
                database, FindingCategory.MEMORY_CORRUPTION
            )
            await _attach(
                database,
                finding_id,
                _observation_evidence(
                    "evidence:obs-rejected",
                    finding_id,
                    "rejected_under_test_conditions",
                    target_binding=target_binding,
                ),
            )
            result = await gate.submit(_review(finding_id))
            assert result.persisted is False
            assert result.decision is not None
            assert "missing_fact:repeatable_crash" in result.decision.reason_codes
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_non_reproducible_trigger_is_not_strong_reproducible_evidence(
    persistence_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        gate = FindingReviewGate(database)
        try:
            finding_id, target_binding = await _seed_finding(
                database, FindingCategory.MEMORY_CORRUPTION
            )
            await _attach(
                database,
                finding_id,
                _observation_evidence(
                    "evidence:obs-flaky",
                    finding_id,
                    "verified_trigger",
                    reproducible=False,
                    target_binding=target_binding,
                ),
            )
            result = await gate.submit(_review(finding_id))
            assert result.persisted is False
            assert result.decision is not None
            assert "missing_strong_reproducible_evidence" in result.decision.reason_codes
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_contract_invalid_observation_carries_no_facts(
    persistence_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        gate = FindingReviewGate(database)
        try:
            finding_id, target_binding = await _seed_finding(
                database, FindingCategory.MEMORY_CORRUPTION
            )
            evidence = _observation_evidence(
                "evidence:obs-invalid", finding_id, "verified_trigger",
                target_binding=target_binding,
            )
            # Simulate a malformed report reaching storage anyway.
            evidence["replay_recipe"]["observation"]["verdict"] = "definitely_hacked"
            await _attach(database, finding_id, evidence)
            result = await gate.submit(_review(finding_id))
            assert result.persisted is False
            assert result.decision is not None
            assert "missing_fact:repeatable_crash" in result.decision.reason_codes
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_crash_observation_does_not_confirm_injection(
    persistence_database_url: str,
) -> None:
    """A target crash proves memory corruption, not a source-to-sink path."""

    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        gate = FindingReviewGate(database)
        try:
            finding_id, target_binding = await _seed_finding(
                database, FindingCategory.INJECTION
            )
            await _attach(
                database,
                finding_id,
                _observation_evidence(
                    "evidence:obs-injection", finding_id, "verified_trigger",
                    target_binding=target_binding,
                ),
            )
            result = await gate.submit(_review(finding_id))
            assert result.persisted is False
            assert result.decision is not None
            assert "missing_fact:source_to_sink_path" in result.decision.reason_codes
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_old_exploitable_poc_records_stay_readable_but_prove_nothing(
    persistence_database_url: str,
) -> None:
    """Legacy rows written by the pre-ADR-036 protocol must not confirm."""

    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        gate = FindingReviewGate(database)
        try:
            finding_id, _target_binding = await _seed_finding(
                database, FindingCategory.MEMORY_CORRUPTION
            )
            legacy_poc = cast(
                Poc,
                {
                    "schema_version": "1.0.0",
                    "id": f"poc:{uuid4().hex[:12]}",
                    "finding_id": finding_id,
                    "kind": PocKind.PROOF_OF_CONCEPT,
                    "status": PocStatus.COMPLETED,
                    "result": PocResult.EXPLOITABLE,
                    "script_ref": "cas://sha256/" + "a" * 64,
                    "run_log_ref": "cas://sha256/" + "b" * 64,
                    "image_digest": "sha256:" + "c" * 64,
                    "permission_mode": PermissionMode.REQUEST_PERMISSION,
                    "resource_budget": budget(),
                    "created_at": TIMESTAMP,
                },
            )
            async with database.transaction() as repositories:
                await repositories.pocs.create(legacy_poc)
                pocs = await repositories.pocs.list_for_finding(finding_id)
                relations = await repositories.findings.list_evidence_relations(finding_id)
            assert [item["id"] for item in pocs] == [legacy_poc["id"]]
            assert pocs[0]["result"] == "exploitable"
            assert relations == []
            result = await gate.submit(_review(finding_id))
            assert result.persisted is False
            assert result.decision is not None
            assert "missing_fact:repeatable_crash" in result.decision.reason_codes
            assert "missing_strong_reproducible_evidence" in result.decision.reason_codes
        finally:
            await database.dispose()

    asyncio.run(scenario())
