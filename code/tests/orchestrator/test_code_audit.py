"""The audit agent investigates through tools; nothing else is trusted."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, cast
from uuid import uuid4

from vulnweaver_artifact_store import LocalContentAddressedStore
from vulnweaver_contracts import (
    AgentRun,
    ArtifactKind,
    BinaryLocation,
    Evidence,
    EvidenceRelation,
    EvidenceStrength,
    EvidenceType,
    FindingEvidence,
    FindingStatus,
    Job,
    JobKind,
    JsonObject,
    PairFunction,
    PermissionMode,
    RunStatus,
    SchemaVersion,
    Severity,
    SourceLocation,
    StructuredFailure,
    ToolIdentity,
    validate_contract,
)
from vulnweaver_model_gateway import ModelCallResult
from vulnweaver_orchestrator import (
    AUDIT_TOOLS,
    AgentLoopBudget,
    AuditStepExecutor,
    AuditWorkspace,
    AuditWorkspaceLimits,
    CodeAuditAgent,
    SemanticAuditJobExecutor,
    SemanticAuditor,
)
from vulnweaver_orchestrator.source_facts import SourceReviewFacts
from vulnweaver_persistence import Database, DatabaseSettings
from vulnweaver_source_analysis import SourceExcerpt
from vulnweaver_tool_runtime import (
    PolicyContext,
    PolicyEngine,
    ScheduledToolCall,
    ToolRegistry,
)

from tests.persistence.factories import artifact, artifact_version, job, project, task

NOW = datetime(2026, 9, 11, 8, 0, tzinfo=UTC)
TIMESTAMP = "2026-09-11T08:00:00Z"
ENDPOINT = "audit/test-model"


class ScriptedPlanner:
    """Return one scripted ActionPlanProposal per call, then finish."""

    def __init__(
        self, proposals: list[dict[str, object]], failure: StructuredFailure | None = None
    ) -> None:
        self._proposals = list(proposals)
        self._failure = failure
        self.calls = 0

    async def complete_structured(self, **kwargs: object) -> ModelCallResult:
        self.calls += 1
        output = (
            self._proposals.pop(0)
            if self._proposals
            else {"schema_version": "1.0.0", "steps": [], "rationale": "nothing further"}
        )
        run = cast(
            AgentRun,
            {
                "schema_version": "1.0.0",
                "id": str(kwargs.get("run_id", "agent-run:stub")),
                "task_id": str(kwargs.get("task_id", "task:stub")),
                "status": RunStatus.FAILED if self._failure else RunStatus.SUCCEEDED,
                "model": ENDPOINT,
                "prompt_hash": "sha256:" + "a" * 64,
                "input_refs": [],
                "decisions": [],
                "token_usage": {"input_tokens": 12, "output_tokens": 8},
                "failure": self._failure,
                "created_at": TIMESTAMP,
                "updated_at": TIMESTAMP,
            },
        )
        return ModelCallResult(output, run, self._failure, "endpoint-1")


class StubFactLoader:
    async def load(self, task_id: str, location: JsonObject) -> SourceReviewFacts:
        excerpt = SourceExcerpt(
            artifact_version_id=str(location["artifact_version_id"]),
            archive_ref="cas://sha256/" + "b" * 64,
            archive_digest="sha256:" + "b" * 64,
            path=str(location["path"]),
            file_digest="sha256:" + "c" * 64,
            start_line=int(location["start_line"]),
            end_line=int(location["end_line"]),
            text="def handle(request):\n    return eval(request)\n",
            truncated=False,
        )
        return SourceReviewFacts(True, None, excerpt)


def step(
    tool: str, arguments: JsonObject, *, step_id: str, refs: list[str]
) -> dict[str, object]:
    return {
        "step_id": step_id,
        "tool_name": tool,
        "tool_version": "1.0.0",
        "input_refs": refs,
        "arguments": arguments,
        "expected_output_types": ["json"],
        "reason": f"investigate via {tool}",
    }


def proposal(steps: list[dict[str, object]], rationale: str) -> dict[str, object]:
    return {"schema_version": "1.0.0", "steps": steps, "rationale": rationale}


def source_function(identifier: str, version_id: str, path: str) -> PairFunction:
    return PairFunction(
        schema_version="1.0.0",
        id=identifier,
        artifact_version_id=version_id,
        name="handle",
        symbol="handle",
        language="python",
        source_location=SourceLocation(
            artifact_version_id=version_id,
            path=path,
            start_line=1,
            start_column=1,
            end_line=2,
            end_column=30,
        ),
        binary_location=None,
        signature="def handle(request)",
        attributes={},
    )


def binary_function(identifier: str, version_id: str) -> PairFunction:
    """Binary PAIR functions carry a *list* of decompiler records."""

    return PairFunction(
        schema_version="1.0.0",
        id=identifier,
        artifact_version_id=version_id,
        name="sub_1050",
        symbol=None,
        language="x86_64",
        source_location=None,
        binary_location=BinaryLocation(
            artifact_version_id=version_id,
            image_base=0x400000,
            virtual_address=0x1050,
            file_offset=0x1050,
            instruction_end=0x10A0,
        ),
        signature=None,
        attributes={
            "pseudocode": [
                {
                    "function_name": "sub_1050",
                    "address": 0x1050,
                    "text": "void sub_1050(char *src) { char buf[32]; strcpy(buf, src); }",
                    "tool_name": "ghidra",
                }
            ]
        },
    )


async def seed(
    database: Database, build_functions: Callable[[str], list[PairFunction]]
) -> tuple[str, str]:
    suffix = uuid4().hex
    version_id = f"artifact-version:{suffix}"
    functions = build_functions(version_id)
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
            )
        )
        if functions:
            await repositories.pair.import_graph(functions, [], [], None, created_at=NOW)
    return suffix, version_id


def audit_job(identifier: str, task_id: str) -> Job:
    return job(
        identifier, task_id=task_id, idempotency_key=identifier, kind=JobKind.SEMANTIC_AUDIT
    )


def test_audit_tools_register_and_enforce_read_only_boundaries() -> None:
    registry = ToolRegistry(AUDIT_TOOLS)
    assert len(registry) == 9
    for spec in registry.snapshot():
        validate_contract("ToolSpec", cast(Any, spec))
        assert spec["approval_required"] is False
        assert spec["network_policy"]["access"] == "none"
        assert spec["filesystem_policy"]["allow_host_paths"] is False

    context = PolicyContext(
        artifact_kinds={"version-1": ArtifactKind.SOURCE_ARCHIVE},
        permission_mode=PermissionMode.FULL_ACCESS,
    )
    engine = PolicyEngine(registry)

    def evaluate(arguments: JsonObject, tool: str = "code-function-list") -> tuple[str, ...]:
        plan = {
            "schema_version": "1.0.0",
            "id": "plan-1",
            "task_id": "task-1",
            "agent_run_id": "run-1",
            "steps": [step(tool, arguments, step_id="s1", refs=["version-1"])],
            "created_at": TIMESTAMP,
        }
        return engine.evaluate(plan, context).reason_codes

    assert evaluate({"limit": 5}, tool="code-function-list") == ()
    assert "host_path_or_traversal" in evaluate({"path_prefix": "/etc"})
    assert "host_path_or_traversal" in evaluate({"name_pattern": "../../etc"})
    # A traversal *rationale* is prose the service never resolves to a path.
    assert (
        evaluate(
            {
                "cwe_id": "CWE-22",
                "title": "path traversal",
                "severity": "high",
                "rationale": "input reaches the sink through ../ segments",
                "path": "src/main.c",
                "start_line": 4,
            },
            tool="finding-report",
        )
        == ()
    )
    assert "invalid_tool_arguments" in evaluate({"limit": 5000}, tool="code-function-list")


def test_workspace_reads_list_shaped_pseudocode(
    persistence_database_url: str, tmp_path: Any
) -> None:
    """Regression: binary pseudocode is a list of records, not a string."""

    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        suffix, version_id = await seed(
            database,
            lambda vid: [binary_function(f"pair-fn:{uuid4().hex}", vid)],
        )
        async with database.transaction() as repositories:
            functions = await repositories.pair.list_functions(version_id)
        assert functions, "binary function must be indexed"
        function_id = functions[0]["id"]

        workspace = AuditWorkspace(
            database,
            LocalContentAddressedStore(tmp_path),
            f"task:{suffix}",
            limits=AuditWorkspaceLimits(),
            fact_loader=StubFactLoader(),
        )
        try:
            await workspace.load()
            assert workspace.function_count == 1
            read = await workspace.read_function(
                function_id=function_id, path=None, start_line=None
            )
            assert read["found"] is True
            assert read["code_kind"] == "pseudocode"
            assert "strcpy" in str(read["code"])

            neighborhood = await workspace.neighborhood(function_id=function_id, depth=1)
            assert neighborhood["found"] is True
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_agent_investigates_then_reports_and_projection_anchors(
    persistence_database_url: str, tmp_path: Any
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        real_path = "src/app.py"
        suffix, version_id = await seed(
            database,
            lambda vid: [source_function(f"pair-fn:{uuid4().hex}", vid, real_path)],
        )
        async with database.transaction() as repositories:
            functions = await repositories.pair.list_functions(version_id)
        assert functions
        # The workspace keys functions by the version that actually holds them.
        function_version = functions[0]["artifact_version_id"]

        planner = ScriptedPlanner(
            [
                proposal(
                    [
                        step(
                            "code-function-list",
                            {"limit": 10},
                            step_id="s1",
                            refs=[function_version],
                        ),
                        step(
                            "static-leads", {}, step_id="s2", refs=[function_version]
                        ),
                    ],
                    "survey the index and the scanner leads",
                ),
                proposal(
                    [
                        step(
                            "finding-report",
                            {
                                "cwe_id": "CWE-95",
                                "title": "eval on request data",
                                "severity": "high",
                                "path": real_path,
                                "start_line": 2,
                                "rationale": "request data reaches eval",
                                "verification_request": "fuzz",
                            },
                            step_id="s3",
                            refs=[function_version],
                        ),
                        step(
                            "finding-report",
                            {
                                "cwe_id": "CWE-89",
                                "title": "invented location",
                                "severity": "medium",
                                "path": "elsewhere/ghost.py",
                                "start_line": 7,
                                "rationale": "hallucinated",
                            },
                            step_id="s4",
                            refs=[function_version],
                        ),
                    ],
                    "report what the code showed",
                ),
            ]
        )
        agent = CodeAuditAgent(database, planner, LocalContentAddressedStore(tmp_path))
        auditor = SemanticAuditor(
            database,
            planner,
            store=LocalContentAddressedStore(tmp_path),
            fact_loader=StubFactLoader(),
            agent=agent,
        )
        executor = SemanticAuditJobExecutor(database, auditor)
        task_id = f"task:{suffix}"
        try:
            result = await executor.execute(
                audit_job(f"job:audit:{suffix}", task_id), asyncio.Event()
            )
            assert result["status"] == "succeeded"
            async with database.transaction() as repositories:
                findings = await repositories.findings.list_for_task(task_id)
                runs = await repositories.agent_runs.list_for_task(task_id)

            # The anchored candidate was recorded; the hallucinated one was not.
            assert len(findings) == 1
            assert findings[0]["cwe_id"] == "CWE-95"
            assert findings[0]["location"]["path"] == real_path
            assert findings[0]["status"] == "candidate"

            # The investigation is visible as decisions on one aggregated run.
            assert len(runs) == 1
            decisions = runs[0]["decisions"]
            recorded = [record["decision"] for record in decisions]
            assert "plan_accepted" in recorded
            assert recorded.count("step_executed") >= 3
            assert len(decisions) >= 4

            # The agent's "verify this dynamically" intent is recorded as
            # provenance: CONTEXTUAL, weight 0, so it can never satisfy the
            # confirmation policy but the evidence chain still shows it.
            async with database.transaction() as repositories:
                relations = await repositories.findings.list_evidence_relations(
                    findings[0]["id"]
                )
                evidence = [
                    await repositories.evidence.get(item["evidence_id"])
                    for item in relations
                ]
            requests = [
                item
                for item in evidence
                if item["replay_recipe"].get("kind") == "dynamic_verification_request"
            ]
            assert len(requests) == 1
            assert requests[0]["replay_recipe"]["verification_tool"] == "fuzz"
            assert requests[0]["strength"] == "contextual"
            contextual = [item for item in relations if item["relation"] == "contextual"]
            assert len(contextual) == 1
            assert contextual[0]["weight"] == 0.0
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_agent_degrades_and_the_auditor_falls_back_to_single_shot(
    persistence_database_url: str, tmp_path: Any
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        real_path = "src/app.py"
        suffix, _ = await seed(
            database,
            lambda vid: [source_function(f"pair-fn:{uuid4().hex}", vid, real_path)],
        )
        unconfigured = StructuredFailure(
            code="model_configuration_error",
            kind="validation",
            message="no route",
            retryable=False,
            details={},
        )
        # The agent's planner is unconfigured; the fixed prompt still answers.
        degraded_planner = ScriptedPlanner([], failure=unconfigured)
        single_shot = ScriptedPlanner(
            [
                {
                    "schema_version": "1.0.0",
                    "summary": "fixed prompt",
                    "findings": [
                        {
                            "cwe_id": "CWE-95",
                            "title": "eval on request data",
                            "severity": "high",
                            "path": real_path,
                            "start_line": 2,
                            "rationale": "fixed-prompt finding",
                        }
                    ],
                }
            ]
        )
        auditor = SemanticAuditor(
            database,
            single_shot,
            store=LocalContentAddressedStore(tmp_path),
            fact_loader=StubFactLoader(),
            agent=CodeAuditAgent(database, degraded_planner, LocalContentAddressedStore(tmp_path)),
        )
        executor = SemanticAuditJobExecutor(database, auditor)
        task_id = f"task:{suffix}"
        try:
            result = await executor.execute(
                audit_job(f"job:audit:{suffix}", task_id), asyncio.Event()
            )
            assert result["status"] == "succeeded"
            async with database.transaction() as repositories:
                findings = await repositories.findings.list_for_task(task_id)
            assert len(findings) == 1
            assert findings[0]["cwe_id"] == "CWE-95"
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_static_leads_are_leads_and_never_become_findings_by_themselves(
    persistence_database_url: str, tmp_path: Any
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        real_path = "src/app.py"
        suffix, version_id = await seed(
            database,
            lambda vid: [source_function(f"pair-fn:{uuid4().hex}", vid, real_path)],
        )
        task_id = f"task:{suffix}"
        async with database.transaction() as repositories:
            functions = await repositories.pair.list_functions(version_id)
            function_version = functions[0]["artifact_version_id"]
            await repositories.evidence.create(
                Evidence(
                    schema_version=SchemaVersion.VALUE_1_0_0,
                    id=f"evidence:{suffix}",
                    type=EvidenceType.TOOL_OUTPUT,
                    strength=EvidenceStrength.SUPPORTING,
                    artifact_ref="cas://sha256/" + "d" * 64,
                    digest="sha256:" + "d" * 64,
                    tool=ToolIdentity(name="semgrep", version="1.0.0", image_digest=None),
                    input_ref="cas://sha256/" + "d" * 64,
                    command_hash=None,
                    exit_code=0,
                    stdout_ref=None,
                    stderr_ref=None,
                    replay_recipe={"kind": "static_analysis_diagnostic", "reproducible": False},
                    created_at=TIMESTAMP,
                )
            )
            await repositories.findings.upsert_candidate(
                cast(
                    Any,
                    {
                        "schema_version": "1.0.0",
                        "id": f"finding:{suffix}",
                        "task_id": task_id,
                        "category": "static_only",
                        "cwe_id": "CWE-78",
                        "title": "scanner lead",
                        "severity": Severity.HIGH,
                        "confidence": 0.6,
                        "location": {
                            "artifact_version_id": function_version,
                            "path": real_path,
                            "start_line": 1,
                            "start_column": 1,
                            "end_line": 2,
                            "end_column": 30,
                        },
                        "dataflow": [],
                        "call_path": [],
                        "status": FindingStatus.CANDIDATE,
                        "evidence_ids": [],
                        "review_ids": [],
                        "poc_ids": [],
                        "fix_suggestion": "scanner suggestion",
                        "created_at": TIMESTAMP,
                    },
                )
            )
            await repositories.findings.link_evidence(
                FindingEvidence(
                    schema_version=SchemaVersion.VALUE_1_0_0,
                    finding_id=f"finding:{suffix}",
                    evidence_id=f"evidence:{suffix}",
                    relation=EvidenceRelation.SUPPORTS,
                    weight=0.6,
                    created_by="test",
                    created_at=TIMESTAMP,
                )
            )

        # The agent looks at the leads and reports nothing.
        planner = ScriptedPlanner(
            [
                proposal(
                    [step("static-leads", {}, step_id="s1", refs=[function_version])],
                    "read the leads",
                )
            ]
        )
        workspace = AuditWorkspace(
            database,
            LocalContentAddressedStore(tmp_path),
            task_id,
            fact_loader=StubFactLoader(),
        )
        try:
            await workspace.load()
            leads = await workspace.static_leads()
            entries = cast(list[JsonObject], leads["leads"])
            assert [entry["cwe_id"] for entry in entries] == ["CWE-78"]
            assert entries[0]["scanners"] == ["semgrep"]

            agent = CodeAuditAgent(database, planner, LocalContentAddressedStore(tmp_path))
            outcome = await agent.audit(
                task_id=task_id,
                job_id=f"job:audit:{suffix}",
                attempt=0,
                run_id="agent-run:test",
            )
            assert outcome.degraded is False
            assert outcome.findings == ()
            assert [item["tool"] for item in outcome.investigation] == [
                "static-leads@1.0.0"
            ]

            async with database.transaction() as repositories:
                findings = await repositories.findings.list_for_task(task_id)
            # The scanner lead is still just a candidate; the agent added nothing.
            assert len(findings) == 1
            assert findings[0]["cwe_id"] == "CWE-78"
        finally:
            await database.dispose()

    asyncio.run(scenario())


class FakeSymbolicRunner:
    """Stand-in for the worker-backed Sandbox Runner call."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, tuple[int, ...]]] = []

    async def __call__(
        self, *, version_id: str, artifact_kind: ArtifactKind, target_addresses: tuple[int, ...]
    ) -> JsonObject:
        self.calls.append((version_id, str(artifact_kind), target_addresses))
        return {
            "targets": list(target_addresses),
            "status": "completed",
            "symbolic_facts": len(target_addresses),
        }


def _symbolic_call(arguments: JsonObject, *, step_id: str = "sym") -> ScheduledToolCall:
    spec = ToolRegistry(AUDIT_TOOLS).resolve("symbolic-execute", "1.0.0")
    return ScheduledToolCall(
        step_id=step_id,
        tool=spec,
        input_refs=(),
        arguments=arguments,
        task_id="task:symbolic",
        plan_id="plan:symbolic",
    )


def test_symbolic_execute_is_refused_without_a_runner_or_a_project_opt_in(
    persistence_database_url: str, tmp_path: Any
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        suffix, _ = await seed(
            database, lambda vid: [binary_function(f"pair-fn:{uuid4().hex}", vid)]
        )
        workspace = AuditWorkspace(
            database, LocalContentAddressedStore(tmp_path), f"task:{suffix}"
        )
        try:
            await workspace.load()
            call = _symbolic_call({"addresses": [0x1050]})

            no_runner = await AuditStepExecutor(workspace).execute(call)
            assert no_runner["failed"] is True
            assert no_runner["reason_code"] == "symbolic.no_runner_configured"

            runner = FakeSymbolicRunner()
            no_opt_in = await AuditStepExecutor(workspace, symbolic_runner=runner).execute(call)
            assert no_opt_in["reason_code"] == "symbolic.dynamic_verification_disabled"
            assert runner.calls == [], "no sandbox run may happen without the project opt-in"
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_symbolic_execute_anchors_addresses_on_the_index_and_caps_runs(
    persistence_database_url: str, tmp_path: Any
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        suffix, _ = await seed(
            database, lambda vid: [binary_function(f"pair-fn:{uuid4().hex}", vid)]
        )
        workspace = AuditWorkspace(
            database, LocalContentAddressedStore(tmp_path), f"task:{suffix}"
        )
        try:
            await workspace.load()
            function_version = workspace.function_refs()[0].version_id
            runner = FakeSymbolicRunner()
            executor = AuditStepExecutor(
                workspace, symbolic_runner=runner, dynamic_verification_enabled=True
            )

            first = await executor.execute(
                _symbolic_call({"addresses": [0x1050, 0xDEADBEEF]}, step_id="sym-1")
            )
            assert first["executed"] is True
            assert first["dropped_addresses"] == 1, "an unindexed address is never executed"
            assert runner.calls[0][0] == function_version
            assert runner.calls[0][2] == (0x1050,)

            # A second planned run is allowed; by then the per-attempt budget is spent.
            await executor.execute(_symbolic_call({"addresses": [0x1050]}, step_id="sym-2"))
            assert len(runner.calls) == 2
            exhausted = await executor.execute(
                _symbolic_call({"addresses": [0x1050]}, step_id="sym-3")
            )
            assert exhausted["failed"] is True
            assert exhausted["reason_code"] == "symbolic.budget_exhausted"
            assert len(runner.calls) == 2, "the cap is enforced here, not by the plan"

            # Addresses that resolve to nothing are reported, and nothing runs.
            idle = FakeSymbolicRunner()
            unresolved = await AuditStepExecutor(
                workspace, symbolic_runner=idle, dynamic_verification_enabled=True
            ).execute(_symbolic_call({"addresses": [0x1]}))
            assert unresolved["reason_code"] == "symbolic.no_anchored_targets"
            assert idle.calls == []
        finally:
            await database.dispose()

    asyncio.run(scenario())


class EndlessPlanner:
    """Never finishes: always proposes one more investigation step."""

    def __init__(self) -> None:
        self.calls = 0

    async def complete_structured(self, **kwargs: object) -> ModelCallResult:
        self.calls += 1
        run = cast(
            AgentRun,
            {
                "schema_version": "1.0.0",
                "id": str(kwargs.get("run_id", "agent-run:stub")),
                "task_id": str(kwargs.get("task_id", "task:stub")),
                "status": RunStatus.SUCCEEDED,
                "model": ENDPOINT,
                "prompt_hash": "sha256:" + "a" * 64,
                "input_refs": [],
                "decisions": [],
                "token_usage": {"input_tokens": 5, "output_tokens": 5},
                "failure": None,
                "created_at": TIMESTAMP,
                "updated_at": TIMESTAMP,
            },
        )
        return ModelCallResult(
            proposal(
                [
                    step(
                        "code-function-list",
                        {"limit": 5},
                        step_id=f"s{self.calls}",
                        refs=[],
                    )
                ],
                "keep investigating",
            ),
            run,
            None,
            "endpoint-1",
        )


def test_an_audit_that_stops_early_never_reports_no_findings(
    persistence_database_url: str, tmp_path: Any
) -> None:
    """An unfinished investigation must not read as "audited, found nothing"."""

    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        real_path = "src/app.py"
        suffix, version_id = await seed(
            database,
            lambda vid: [source_function(f"pair-fn:{uuid4().hex}", vid, real_path)],
        )
        # A finite budget makes the loop stop while the model still wants more.
        agent = CodeAuditAgent(
            database,
            EndlessPlanner(),
            LocalContentAddressedStore(tmp_path),
            budget=AgentLoopBudget(max_planning_rounds=2),
        )
        auditor = SemanticAuditor(
            database,
            EndlessPlanner(),
            store=LocalContentAddressedStore(tmp_path),
            fact_loader=StubFactLoader(),
            agent=agent,
        )
        executor = SemanticAuditJobExecutor(database, auditor)
        task_id = f"task:{suffix}"
        try:
            result = await executor.execute(
                audit_job(f"job:audit:{suffix}", task_id), asyncio.Event()
            )
            assert result["status"] == "failed"
            assert result["failure"] is not None
            assert result["failure"]["code"] == "semantic_audit.loop_not_completed"
            async with database.transaction() as repositories:
                findings = await repositories.findings.list_for_task(task_id)
                runs = await repositories.agent_runs.list_for_task(task_id)
            assert findings == []
            # The incomplete run is still on record, with its failure code.
            assert len(runs) == 1
            assert runs[0]["status"] == "failed"
            assert runs[0]["failure"]["code"] == "loop_planning_round_budget_exhausted"
        finally:
            await database.dispose()

    asyncio.run(scenario())
