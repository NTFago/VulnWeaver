"""Agent-led dynamic verification: the audit's fuzz requests drive dispatch."""

from __future__ import annotations

import asyncio
from typing import Any
from uuid import uuid4

from vulnweaver_artifact_store import LocalContentAddressedStore
from vulnweaver_orchestrator import CodeAuditAgent, SemanticAuditor
from vulnweaver_persistence import Database, DatabaseSettings

from tests.orchestrator.test_code_audit import (
    ScriptedPlanner,
    StubFactLoader,
    audit_job,
    proposal,
    seed,
    source_function,
    step,
)


class RecordingFuzzDispatcher:
    """Record the finding ids the auditor asks to fuzz."""

    def __init__(self, *, opted_in: bool) -> None:
        self.opted_in = opted_in
        self.requested: list[str] = []

    async def schedule_finding_in_transaction(self, repositories, finding_id: str):
        # Mirror the real scheduler's gate so the test exercises the same path.
        finding = await repositories.findings.get(finding_id)
        task = await repositories.tasks.get(finding["task_id"], for_update=True)
        project = await repositories.projects.get(task["project_id"])
        if not project["exploit_validation_enabled"]:
            return None
        self.requested.append(finding_id)
        return f"job:fuzz:{finding_id}"


def _report_step(refs: list[str], *, fuzz: bool, index: int):
    arguments = {
        "cwe_id": "CWE-120" if fuzz else "CWE-89",
        "title": f"candidate {index}",
        "severity": "high",
        "path": "src/app.py",
        "start_line": 2,
        "rationale": "attacker data reaches the sink",
        "constraint": "untrusted input must not reach the sensitive sink",
    }
    if fuzz:
        arguments["verification_request"] = "fuzz"
        arguments["verification_reason"] = "reachability cannot be settled by reading"
    return step("finding-report", arguments, step_id=f"s{index}", refs=refs)


def _run(persistence_database_url: str, scenario) -> None:
    asyncio.run(scenario())


async def _set_opt_in(database, enabled: bool) -> None:
    from sqlalchemy import update
    from vulnweaver_persistence.models import projects

    # The Project repository has no update API; the opt-in flip is a test
    # fixture concern, so it goes through the engine directly.
    engine = database.engine

    async with engine.begin() as connection:
        await connection.execute(
            update(projects).values(exploit_validation_enabled=enabled)
        )


def test_agent_fuzz_request_dispatches_at_audit_settlement(
    persistence_database_url: str, tmp_path: Any
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        suffix, version_id = await seed(
            database,
            lambda vid: [source_function(f"pair-fn:{uuid4().hex}", vid, "src/app.py")],
        )
        await _set_opt_in(database, True)
        functions = await _functions(database, version_id)
        refs = [functions[0]["artifact_version_id"]]

        planner = ScriptedPlanner(
            [
                proposal(
                    [
                        step(
                            "code-function-read", {"function_id": functions[0]["id"]},
                            step_id="read", refs=refs,
                        ),
                        _report_step(refs, fuzz=True, index=1),
                        _report_step(refs, fuzz=False, index=2),
                    ],
                    "one candidate needs dynamic proof",
                ),
            ]
        )
        dispatcher = RecordingFuzzDispatcher(opted_in=True)
        agent = CodeAuditAgent(
            database, planner, LocalContentAddressedStore(tmp_path),
            fact_loader=StubFactLoader(),
        )
        auditor = SemanticAuditor(
            database,
            planner,
            store=LocalContentAddressedStore(tmp_path),
            fact_loader=StubFactLoader(),
            agent=agent,
            fuzz_dispatcher=dispatcher,
        )
        outcome = await auditor.audit(
            audit_job(f"job:audit:{suffix}", f"task:{suffix}")
        )
        assert outcome.finding_ids, "the candidate was not anchored"
        assert len(dispatcher.requested) == 1, dispatcher.requested
        await database.dispose()

    _run(persistence_database_url, scenario)


def test_fuzz_request_without_opt_in_dispatches_nothing(
    persistence_database_url: str, tmp_path: Any
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        suffix, version_id = await seed(
            database,
            lambda vid: [source_function(f"pair-fn:{uuid4().hex}", vid, "src/app.py")],
        )
        functions = await _functions(database, version_id)
        refs = [functions[0]["artifact_version_id"]]
        planner = ScriptedPlanner(
            [
                proposal(
                    [
                        step(
                            "code-function-read", {"function_id": functions[0]["id"]},
                            step_id="read", refs=refs,
                        ),
                        _report_step(refs, fuzz=True, index=1),
                    ],
                    "needs dynamic proof but the project never opted in",
                ),
            ]
        )
        dispatcher = RecordingFuzzDispatcher(opted_in=False)
        agent = CodeAuditAgent(
            database, planner, LocalContentAddressedStore(tmp_path),
            fact_loader=StubFactLoader(),
        )
        auditor = SemanticAuditor(
            database,
            planner,
            store=LocalContentAddressedStore(tmp_path),
            fact_loader=StubFactLoader(),
            agent=agent,
            fuzz_dispatcher=dispatcher,
        )
        await auditor.audit(audit_job(f"job:audit:{suffix}", f"task:{suffix}"))
        assert dispatcher.requested == []
        await database.dispose()

    _run(persistence_database_url, scenario)


async def _functions(database, version_id):
    async with database.transaction() as repositories:
        return await repositories.pair.list_functions(version_id)
