"""The audit agent's pre-flight analysis baseline (tool-work provenance)."""

from __future__ import annotations

import asyncio
import io
import json
import uuid
from pathlib import Path
from typing import cast

from vulnweaver_artifact_store import LocalContentAddressedStore
from vulnweaver_contracts import (
    Artifact,
    ArtifactKind,
    ArtifactVersion,
    JsonObject,
)
from vulnweaver_orchestrator.audit_tools import AuditWorkspace
from vulnweaver_orchestrator.code_audit import CodeAuditAgent
from vulnweaver_persistence import Database, DatabaseSettings

from tests.persistence.factories import TIMESTAMP, project, task

_DOCUMENT: JsonObject = {
    "format": "pe",
    "architecture": "x86_64",
    "packed": True,
    "packer": "UPX",
    "compiler": None,
    "entry_point": 4198405,
    "functions": [],
    "instructions": [],
    "basic_blocks": [],
    "xrefs": [],
    "pseudocode": [],
    "symbolic_facts": [{"function_address": 4198405, "status": "completed"}],
    "strings": [],
    "imports": [],
    "tool_runs": [
        {
            "tool_name": "ghidra",
            "tool_version": "11.4",
            "status": "succeeded",
            "exit_code": 0,
            "reason": None,
            "raw_output": None,
        }
    ],
    "coverage": {
        "functions": {
            "offered": 20001,
            "retained": 20000,
            "limit": 20000,
            "truncated": True,
            "reason": "1 unique items dropped: functions limit 20000 reached",
        },
        "instructions": {
            "offered": 10, "retained": 10, "limit": 200000, "truncated": False, "reason": None,
        },
        "basic_blocks": {
            "offered": 10, "retained": 10, "limit": 100000, "truncated": False, "reason": None,
        },
        "xrefs": {
            "offered": 10, "retained": 10, "limit": 200000, "truncated": False, "reason": None,
        },
        "pseudocode": {
            "offered": 10, "retained": 10, "limit": 20000, "truncated": False, "reason": None,
        },
        "symbolic_facts": {
            "offered": 1, "retained": 1, "limit": 8, "truncated": False, "reason": None,
        },
        "imports": {
            "offered": 0, "retained": 0, "limit": 20000, "truncated": False, "reason": None,
        },
        "strings": {
            "offered": 0, "retained": 0, "limit": 50000, "truncated": False, "reason": None,
        },
        "complete": False,
    },
}


async def _seed(database: Database, store: LocalContentAddressedStore, suffix: str) -> str:
    """Project + task whose only version is a binary-analysis result."""

    version_id = f"artifact-version:{suffix}"
    stored = store.put_stream(
        io.BytesIO(json.dumps(_DOCUMENT).encode()), max_bytes=1024 * 1024
    )
    async with database.transaction() as repositories:
        await repositories.projects.add(project(f"project:{suffix}"))
        await repositories.artifacts.add(
            Artifact(
                schema_version="1.0.0",
                id=f"artifact:{suffix}",
                project_id=f"project:{suffix}",
                kind=ArtifactKind.DERIVED,
                current_version_id=version_id,
                created_at=TIMESTAMP,
            )
        )
        await repositories.artifacts.add_version(
            ArtifactVersion(
                schema_version="1.0.0",
                id=version_id,
                artifact_id=f"artifact:{suffix}",
                digest=stored.digest,
                object_ref=stored.object_ref,
                parent_version_id=None,
                generation_config={
                    "format": "binary-analysis-result",
                    "reuse_key": "sha256:" + "f" * 64,
                    "target_addresses": [4198405],
                },
                created_at=TIMESTAMP,
            )
        )
        await repositories.tasks.create(
            task(
                f"task:{suffix}",
                project_id=f"project:{suffix}",
                artifact_version_ids=[version_id],
                idempotency_key=f"task:{suffix}-key",
            )
        )
    return f"task:{suffix}"


def test_workspace_reports_the_pre_audit_analysis_baseline(
    persistence_database_url: str, tmp_path: Path
) -> None:
    async def scenario() -> None:
        suffix = uuid.uuid4().hex[:12]
        database = Database(DatabaseSettings(persistence_database_url))
        store = LocalContentAddressedStore(tmp_path)
        try:
            task_id = await _seed(database, store, suffix)
            workspace = AuditWorkspace(database, store, task_id)
            await workspace.load()
            baseline = await workspace.analysis_baseline()
            binary = baseline["binary"]
            assert isinstance(binary, dict)
            assert binary["analysis_version_id"] == f"artifact-version:{suffix}"
            assert binary["produced_at"] == TIMESTAMP
            assert binary["symbolic_targets"] == [4198405]
            assert binary["tool_runs"] == [
                {"tool": "ghidra", "version": "11.4", "status": "succeeded"}
            ]
            assert binary["symbolic_facts"] == 1
            # CR-08: truncation recorded by the import chain reaches the baseline
            # so the agent knows the retained function set is not the full image.
            assert binary["truncated_collections"] == ["functions"]
            # No source archive in this task: the source slot stays empty.
            assert baseline["source_index"] is None
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_artifact_facts_summary_exposes_coverage(
    persistence_database_url: str, tmp_path: Path
) -> None:
    async def scenario() -> None:
        suffix = uuid.uuid4().hex[:12]
        database = Database(DatabaseSettings(persistence_database_url))
        store = LocalContentAddressedStore(tmp_path)
        try:
            task_id = await _seed(database, store, suffix)
            workspace = AuditWorkspace(database, store, task_id)
            await workspace.load()
            summary = await workspace.artifact_facts(kind="summary")
            assert summary["available"] is True
            coverage = summary["coverage"]
            assert isinstance(coverage, dict)
            functions = coverage["functions"]
            assert isinstance(functions, dict)
            assert functions["truncated"] is True
            assert functions["retained"] == 20000
            assert coverage["complete"] is False
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_agent_context_carries_the_analysis_baseline(
    persistence_database_url: str, tmp_path: Path
) -> None:
    async def scenario() -> None:
        suffix = uuid.uuid4().hex[:12]
        database = Database(DatabaseSettings(persistence_database_url))
        store = LocalContentAddressedStore(tmp_path)
        try:
            task_id = await _seed(database, store, suffix)
            workspace = AuditWorkspace(database, store, task_id)
            await workspace.load()
            agent = CodeAuditAgent(database, None, store)
            context = await agent._context(task_id, workspace)  # noqa: SLF001 - wiring check
            assert isinstance(context.get("analysis_baseline"), dict)
            binary = cast(JsonObject, context["analysis_baseline"])["binary"]
            assert isinstance(binary, dict) and binary["tool_runs"]
        finally:
            await database.dispose()

    asyncio.run(scenario())
