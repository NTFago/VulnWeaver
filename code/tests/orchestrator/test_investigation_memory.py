"""Investigation memory: the audit agent's own conclusions, across tasks."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any, cast

from vulnweaver_artifact_store import LocalContentAddressedStore
from vulnweaver_contracts import RunStatus, ToolIdentity
from vulnweaver_model_gateway import ModelCallResult
from vulnweaver_orchestrator import (
    CodeAuditAgent,
    DatabaseInvestigationMemory,
    SemanticAuditor,
    build_memory_document,
    memory_context_entry,
)
from vulnweaver_persistence import Database, DatabaseSettings

from tests.persistence.factories import TIMESTAMP

NOW = datetime(2026, 9, 28, 8, 0, tzinfo=UTC)


def test_build_memory_document_bounds_and_shape() -> None:
    document = build_memory_document(
        task_id="task:1",
        project_id="project:1",
        run_id="agent-run:1",
        created_at=TIMESTAMP,
        findings=[{"cwe_id": f"CWE-{n}", "title": "t"} for n in range(80)],
        dropped_candidates=[{"path": f"ghost/{n}.py"} for n in range(40)],
        investigation=[{"step_id": f"s{n}"} for n in range(40)],
        completed=True,
        source_version_id="v1",
        binary_version_id="",
    )
    assert len(document["findings"]) == 64
    assert len(document["dropped_candidates"]) == 32
    assert len(document["investigation"]) == 24
    assert document["completed"] is True

    entry = memory_context_entry(document)
    assert entry["completed"] is True
    assert len(entry["investigation"]) == 12
    assert entry["task_id"] == "task:1"


def test_memory_context_entry_tolerates_partial_documents() -> None:
    entry = memory_context_entry({"task_id": "task:x"})
    assert entry["completed"] is False
    assert entry["findings"] == []
    assert entry["dropped_candidates"] == []


def test_memory_write_and_latest_round_trip(
    persistence_database_url: str, tmp_path: Any
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        store = LocalContentAddressedStore(tmp_path / "cas")
        memory = DatabaseInvestigationMemory(database, store)
        async with database.transaction() as repositories:
            from tests.persistence.factories import project as project_row

            await repositories.projects.add(project_row("project:1"))
        document_one = build_memory_document(
            task_id="task:1",
            project_id="project:1",
            run_id="agent-run:one",
            created_at="2026-09-28T07:00:00Z",
            findings=[{"cwe_id": "CWE-79", "title": "xss"}],
            dropped_candidates=[{"path": "ghost.py", "start_line": 3}],
            investigation=[],
            completed=True,
        )
        document_two = build_memory_document(
            task_id="task:2",
            project_id="project:1",
            run_id="agent-run:two",
            created_at="2026-09-28T08:00:00Z",
            findings=[],
            dropped_candidates=[],
            investigation=[],
            completed=False,
        )
        first = await memory.write(
            project_id="project:1",
            parent_version_id="",
            document=document_one,
            produced_by=ToolIdentity(
                name="semantic-audit-agent", version="1.0.0", image_digest=None
            )
        )
        second = await memory.write(
            project_id="project:1",
            parent_version_id="",
            document=document_two,
            produced_by=ToolIdentity(
                name="semantic-audit-agent", version="1.0.0", image_digest=None
            )
        )
        assert first and second and first != second

        latest = await memory.latest("project:1")
        assert [item["run_id"] for item in latest] == ["agent-run:two", "agent-run:one"]
        assert latest[0]["completed"] is False
        assert latest[1]["findings"] == [{"cwe_id": "CWE-79", "title": "xss"}]

        # A project without memory starts clean, never errors.
        assert await memory.latest("project:never") == []
        await database.dispose()

    asyncio.run(scenario())


class _ContextCapturingPlanner:
    """Read one function, then finish, recording the messages the loop sent."""

    def __init__(self, function_id: str, refs: list[str]) -> None:
        self.captured: list[str] = []
        self._function_id = function_id
        self._refs = refs

    async def complete_structured(self, **kwargs: object) -> ModelCallResult:
        messages = cast(list[dict[str, str]], kwargs["messages"])
        self.captured.append(json.dumps(messages, ensure_ascii=False))
        if self._function_id:
            output: dict[str, object] = {
                "schema_version": "1.0.0",
                "steps": [
                    {
                        "step_id": "read",
                        "tool_name": "code-function-read",
                        "tool_version": "1.0.0",
                        "input_refs": list(self._refs),
                        "arguments": {"function_id": self._function_id},
                        "expected_output_types": ["json"],
                        "reason": "ground the audit in code",
                    }
                ],
                "rationale": "read the function before concluding",
            }
            self._function_id = ""
        else:
            output = {"schema_version": "1.0.0", "steps": [], "rationale": "nothing to do"}
        return ModelCallResult(
            output,
            _run_stub(),
            None,
            "endpoint-memory",
        )


def _run_stub() -> Any:
    return {
        "schema_version": "1.0.0",
        "id": "agent-run:stub",
        "task_id": "task:1",
        "status": RunStatus.SUCCEEDED,
        "model": "audit/test-model",
        "prompt_hash": "0" * 64,
        "input_refs": [],
        "decisions": [],
        "token_usage": {"input_tokens": 1, "output_tokens": 1},
        "failure": None,
        "created_at": TIMESTAMP,
        "updated_at": TIMESTAMP,
    }


def test_prior_memory_reaches_the_next_audit_context(
    persistence_database_url: str, tmp_path: Any
) -> None:
    async def scenario() -> None:
        from tests.orchestrator.test_code_audit import (
            StubFactLoader,
            seed,
            source_function,
        )

        database = Database(DatabaseSettings(persistence_database_url))
        store = LocalContentAddressedStore(tmp_path / "cas")
        suffix, version_id = await seed(
            database,
            lambda vid: [source_function(f"pair-fn:{vid[-6:]}", vid, "src/app.py")],
        )
        project_id = f"project:{suffix}"
        task_id = f"task:{suffix}"

        # An earlier investigation left conclusions behind.
        memory = DatabaseInvestigationMemory(database, store)
        await memory.write(
            project_id=project_id,
            parent_version_id=version_id,
            document=build_memory_document(
                task_id=task_id,
                project_id=project_id,
                run_id="agent-run:prior",
                created_at="2026-09-01T08:00:00Z",
                findings=[{"cwe_id": "CWE-95", "title": "eval on request data"}],
                dropped_candidates=[{"path": "elsewhere/ghost.py", "start_line": 7}],
                investigation=[],
                completed=True,
            ),
            produced_by=ToolIdentity(
                name="semantic-audit-agent", version="1.0.0", image_digest=None
            )
        )

        # The planner reads the one indexed function before concluding; an
        # investigation that never reads code falls back instead of settling.
        async with database.transaction() as repositories:
            functions = await repositories.pair.list_functions(version_id)
        planner = _ContextCapturingPlanner(
            functions[0]["id"], [functions[0]["artifact_version_id"]]
        )
        agent = CodeAuditAgent(database, planner, store, fact_loader=StubFactLoader())
        auditor = SemanticAuditor(database, planner, store=store, agent=agent)
        await auditor.audit(_audit_job(f"job:memory:{suffix}", task_id))

        assert planner.captured, "the loop never called the model"
        joined = "\n".join(planner.captured)
        assert "prior_investigations" in joined
        assert "CWE-95" in joined
        assert "elsewhere/ghost.py" in joined

        # This audit wrote its own conclusions back as the newest memory entry.
        latest = await memory.latest(project_id)
        assert latest and latest[0]["run_id"] != "agent-run:prior"
        assert latest[0]["run_id"].startswith("agent-run:")
        assert latest[0]["completed"] is True
        await database.dispose()

    asyncio.run(scenario())


def _audit_job(identifier: str, task_id: str) -> Any:
    from tests.orchestrator.test_code_audit import audit_job

    return audit_job(identifier, task_id)
