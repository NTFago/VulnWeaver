from __future__ import annotations

import asyncio
from typing import cast

from vulnweaver_contracts import Evidence, EvidenceStrength, EvidenceType, ToolIdentity
from vulnweaver_persistence import Database, DatabaseSettings


def test_evidence_repository_is_immutable_and_idempotent(persistence_database_url: str) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        try:
            value = cast(
                Evidence,
                {
                    "schema_version": "1.0.0",
                    "id": "evidence:tool-output",
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
                    "replay_recipe": {"kind": "static_analysis", "reproducible": True},
                    "created_at": "2026-09-08T10:00:00Z",
                },
            )
            async with database.transaction() as repositories:
                assert await repositories.evidence.create(value) == value
                assert await repositories.evidence.create(value) == value
                assert await repositories.evidence.get(value["id"]) == value
                assert await repositories.evidence.list_for_input(value["input_ref"]) == [value]
        finally:
            await database.dispose()

    asyncio.run(scenario())
