"""The audit agent investigates through tools; nothing else is trusted."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, cast
from unittest.mock import AsyncMock, patch
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
    AUDIT_CHECKPOINT_NODE,
    AUDIT_TOOLS,
    AgentLoopBudget,
    AuditStepExecutor,
    AuditWorkspace,
    AuditWorkspaceLimits,
    CodeAuditAgent,
    SemanticAuditJobExecutor,
    SemanticAuditor,
)
from vulnweaver_orchestrator.audit_tools import AuditFunctionRef
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
        self.messages: list[list[dict[str, str]]] = []

    async def complete_structured(self, **kwargs: object) -> ModelCallResult:
        self.calls += 1
        self.messages.append(cast(list[dict[str, str]], kwargs["messages"]))
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


def step(tool: str, arguments: JsonObject, *, step_id: str, refs: list[str]) -> dict[str, object]:
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


def test_source_search_counts_unique_files_before_applying_file_budget() -> None:
    async def scenario() -> None:
        workspace = AuditWorkspace(
            cast(Database, None), cast(Any, None), "task:test",
            limits=AuditWorkspaceLimits(max_search_files=2),
        )
        workspace._functions = [
            AuditFunctionRef("version:test", source_function("function:a", "version:test", "a.py")),
            AuditFunctionRef("version:test", source_function("function:b", "version:test", "a.py")),
            AuditFunctionRef("version:test", source_function("function:c", "version:test", "b.py")),
        ]
        report_call = ScheduledToolCall(
            step_id="report", tool=ToolRegistry(AUDIT_TOOLS).resolve("finding-report", "1.0.0"),
            input_refs=(), task_id="task:test", plan_id="plan:test",
            arguments={
                "cwe_id": "CWE-95", "title": "second file issue", "severity": "high",
                "path": "b.py", "start_line": 1, "rationale": "needle in code",
                "constraint": "untrusted input must not reach eval",
            },
        )
        reporter = AuditStepExecutor(workspace)
        unread = await reporter.execute(report_call)
        assert unread["reason_code"] == "finding_report.code_not_read"
        assert reporter.reported == []
        with patch.object(workspace, "_read_file", new_callable=AsyncMock) as reader:
            reader.side_effect = lambda version, path: {
                "a.py": "no match\n", "b.py": "needle\n"
            }[path]
            result = await workspace.search(pattern="needle", scope="source", limit=10)
        assert result["files_available"] == 2
        assert result["files_scanned"] == 2
        assert result["files_unscanned"] == 0
        assert result["matches"][0]["path"] == "b.py"
        assert reader.await_count == 2
        assert (await reporter.execute(report_call))["recorded"] is True

    asyncio.run(scenario())


def test_truncated_function_excerpt_does_not_authorize_unread_tail() -> None:
    class TruncatedLoader:
        async def load(self, task_id: str, location: JsonObject) -> SourceReviewFacts:
            return SourceReviewFacts(
                True, "source_excerpt_truncated",
                SourceExcerpt(
                    artifact_version_id="version:test", archive_ref="cas://sha256/" + "a" * 64,
                    archive_digest="sha256:" + "a" * 64, path="a.py",
                    file_digest="sha256:" + "b" * 64, start_line=1, end_line=1,
                    text="def handle(request):\n", truncated=True,
                ),
            )

    async def scenario() -> None:
        workspace = AuditWorkspace(
            cast(Database, None), cast(Any, None), "task:test",
            fact_loader=cast(Any, TruncatedLoader()),
        )
        ref = AuditFunctionRef(
            "version:test", source_function("function:a", "version:test", "a.py")
        )
        workspace._functions = [ref]
        workspace._functions_by_id = {ref.function["id"]: ref}
        await workspace.read_function(function_id=ref.function["id"], path=None, start_line=None)
        assert workspace.has_read_reported_code(path="a.py", start_line=1, address=None)
        assert not workspace.has_read_reported_code(path="a.py", start_line=2, address=None)

    asyncio.run(scenario())


def test_read_proof_is_scoped_to_the_artifact_version() -> None:
    """CR-06: reading one version's copy of a path proves nothing about another.

    Two versions of one project may carry the same path; a report anchored to
    version B's function needs a read of version B's file, not version A's.
    """

    class VersionedLoader:
        async def load(self, task_id: str, location: JsonObject) -> SourceReviewFacts:
            version = str(location["artifact_version_id"])
            return SourceReviewFacts(
                True, None,
                SourceExcerpt(
                    artifact_version_id=version,
                    archive_ref="cas://sha256/" + "a" * 64,
                    archive_digest="sha256:" + "a" * 64,
                    path=str(location["path"]),
                    file_digest="sha256:" + "b" * 64,
                    start_line=1,
                    end_line=2,
                    text="def handle(request):\n    return eval(request)\n",
                    truncated=False,
                ),
            )

    async def scenario() -> None:
        workspace = AuditWorkspace(
            cast(Database, None), cast(Any, None), "task:test",
            fact_loader=cast(Any, VersionedLoader()),
        )
        ref_a = AuditFunctionRef(
            "version:a", source_function("function:a", "version:a", "src/app.py")
        )
        ref_b = AuditFunctionRef(
            "version:b", source_function("function:b", "version:b", "src/app.py")
        )
        workspace._functions = [ref_a, ref_b]
        workspace._functions_by_id = {ref.function["id"]: ref for ref in (ref_a, ref_b)}
        # Read version B's copy of the shared path.
        await workspace.read_function(function_id="function:b", path=None, start_line=None)
        # The reported location resolves to version A (the audit anchor version):
        # version B's read does not authorize it.
        assert not workspace.has_read_reported_code(
            path="src/app.py", start_line=1, address=None
        )
        # Reading version A's own copy authorizes the report.
        await workspace.read_function(function_id="function:a", path=None, start_line=None)
        assert workspace.has_read_reported_code(path="src/app.py", start_line=1, address=None)

    asyncio.run(scenario())


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
    return job(identifier, task_id=task_id, idempotency_key=identifier, kind=JobKind.SEMANTIC_AUDIT)


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
                "constraint": "path components must remain under the project root",
                "path": "src/main.c",
                "start_line": 4,
            },
            tool="finding-report",
        )
        == ()
    )
    assert "invalid_tool_arguments" in evaluate({"limit": 5000}, tool="code-function-list")
    assert "invalid_tool_arguments" in evaluate(
        {
            "cwe_id": "CWE-95",
            "title": "eval on request data",
            "severity": "high",
            "rationale": "request data reaches eval",
            "path": "src/app.py",
            "start_line": 4,
        },
        tool="finding-report",
    )


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
                        step("static-leads", {}, step_id="s2", refs=[function_version]),
                        step(
                            "code-function-read", {"function_id": functions[0]["id"]},
                            step_id="s-read", refs=[function_version],
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
                                "constraint": "untrusted request data must not reach eval",
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
                                "constraint": "reported source location must exist in the index",
                            },
                            step_id="s4",
                            refs=[function_version],
                        ),
                    ],
                    "report what the code showed",
                ),
            ]
        )
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
                relations = await repositories.findings.list_evidence_relations(findings[0]["id"])
                evidence = [
                    await repositories.evidence.get(item["evidence_id"]) for item in relations
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
                            "constraint": "untrusted request data must not reach eval",
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
            # Leads are matched on the task input version's object_ref, exactly
            # as production evidence references it.
            input_version = await repositories.artifacts.get_version(version_id)
            input_ref = input_version["object_ref"]
            await repositories.evidence.create(
                Evidence(
                    schema_version=SchemaVersion.VALUE_1_0_0,
                    id=f"evidence:{suffix}",
                    type=EvidenceType.TOOL_OUTPUT,
                    strength=EvidenceStrength.SUPPORTING,
                    artifact_ref=input_ref,
                    digest=input_version["digest"],
                    tool=ToolIdentity(name="semgrep", version="1.0.0", image_digest=None),
                    input_ref=input_ref,
                    command_hash=None,
                    exit_code=0,
                    stdout_ref=None,
                    stderr_ref=None,
                    replay_recipe={
                        "kind": "static_analysis_diagnostic",
                        "reproducible": False,
                        "diagnostic_selector": {
                            "tool_name": "semgrep",
                            "rule_id": "py.command-injection",
                            "cwe_id": "CWE-78",
                            "severity": "high",
                            "message": "subprocess call with request data",
                            "location": {
                                "artifact_version_id": function_version,
                                "path": real_path,
                                "start_line": 1,
                            },
                        },
                    },
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
            assert entries[0]["scanner"] == "semgrep"
            assert entries[0]["rule_id"] == "py.command-injection"
            assert entries[0]["path"] == real_path

            agent = CodeAuditAgent(database, planner, LocalContentAddressedStore(tmp_path))
            outcome = await agent.audit(
                task_id=task_id,
                job_id=f"job:audit:{suffix}",
                attempt=0,
                run_id="agent-run:test",
            )
            assert outcome.degraded is False
            assert outcome.findings == ()
            assert [item["tool"] for item in outcome.investigation] == ["static-leads@1.0.0"]

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
        workspace = AuditWorkspace(database, LocalContentAddressedStore(tmp_path), f"task:{suffix}")
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
        workspace = AuditWorkspace(database, LocalContentAddressedStore(tmp_path), f"task:{suffix}")
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


def _interrupted_checkpoint_state(job_id: str, run_id: str, function_version: str) -> JsonObject:
    """What the progress callback would have persisted after round 2 crashed."""

    def step_document(step_id: str, plan_suffix: str, output: dict[str, object]) -> JsonObject:
        return cast(
            JsonObject,
            {
                "step_id": step_id,
                "tool_name": "code-function-list",
                "tool_version": "1.0.0",
                "plan_id": f"{run_id}-plan-{plan_suffix}",
                "succeeded": True,
                "output": output,
                "artifact_refs": [function_version],
                "failure_code": None,
            },
        )

    first = step_document("s1", "1", {"functions": 1})
    second = step_document("s2", "2", {"summary": "surveyed the index"})
    return cast(
        JsonObject,
        {
            "schema_version": "1.0.0",
            "job_id": job_id,
            "run_id": run_id,
            "completed": False,
            "rounds": 2,
            "decisions": [
                {
                    "sequence": 1,
                    "decision": "plan_accepted",
                    "reason": "plan approved with 1 step(s): survey the index",
                    "created_at": TIMESTAMP,
                },
                {
                    "sequence": 2,
                    "decision": "step_executed",
                    "reason": "step s1 via code-function-list",
                    "created_at": TIMESTAMP,
                },
                {
                    "sequence": 3,
                    "decision": "plan_accepted",
                    "reason": "plan approved with 1 step(s): check the entrypoints",
                    "created_at": TIMESTAMP,
                },
                {
                    "sequence": 4,
                    "decision": "step_executed",
                    "reason": "step s2 via code-function-list",
                    "created_at": TIMESTAMP,
                },
            ],
            "steps": [first, second],
            "last_round_steps": [second],
            "journal": [
                {
                    "round": 1,
                    "kind": "step",
                    "step_id": "s1",
                    "tool": "code-function-list@1.0.0",
                    "outcome": "ok",
                    "summary": "listed 1 indexed function",
                }
            ],
            "reported": [
                {
                    "cwe_id": "CWE-95",
                    "title": "eval on request data",
                    "severity": "high",
                    "rationale": "request data reaches eval",
                    "constraint": "untrusted request data must not reach eval",
                    "path": "src/app.py",
                    "start_line": 2,
                    "end_line": None,
                    "address": None,
                    "verification_request": None,
                    "verification_reason": None,
                    "step_id": "s2",
                }
            ],
            "usage": {"input_tokens": 900, "output_tokens": 120},
            "artifact_refs": [function_version],
            "model_label": "audit/test-model",
        },
    )


def test_audit_resumes_from_an_interrupted_checkpoint(
    persistence_database_url: str, tmp_path: Any
) -> None:
    async def scenario() -> None:
        from vulnweaver_orchestrator import InMemoryCheckpointStore

        database = Database(DatabaseSettings(persistence_database_url))
        suffix, version_id = await seed(
            database,
            lambda vid: [source_function(f"pair-fn:{uuid4().hex}", vid, "src/app.py")],
        )
        async with database.transaction() as repositories:
            functions = await repositories.pair.list_functions(version_id)
        function_version = functions[0]["artifact_version_id"]
        task_id = f"task:{suffix}"
        job_id = f"job:audit:{suffix}"
        run_id = f"agent-run:semantic-audit:{suffix}-agent"

        checkpoints = InMemoryCheckpointStore()
        await checkpoints.save(
            task_id,
            AUDIT_CHECKPOINT_NODE,
            _interrupted_checkpoint_state(job_id, run_id, function_version),
            created_at=TIMESTAMP,
        )
        # The resumed model immediately concludes: it must see the prior round's
        # observation in its first message rather than starting from zero.
        planner = ScriptedPlanner([])
        agent = CodeAuditAgent(
            database,
            planner,
            LocalContentAddressedStore(tmp_path),
            checkpoint_store=checkpoints,
        )
        outcome = await agent.audit(
            task_id=task_id,
            job_id=job_id,
            attempt=2,
            run_id=f"{run_id}-retry",
            input_refs=(version_id,),
        )
        assert outcome.completed
        assert planner.calls == 1
        assert outcome.steps and outcome.steps[0].step_id == "s1"
        # Round 2 arrives verbatim; round 1 arrives as its compacted journal
        # digest, so the takeover loses no investigation history.
        first_user = json.loads(planner.messages[0][1]["content"])
        assert first_user["last_feedback"]["planning_round"] == 2
        assert [entry["summary"] for entry in first_user["investigation_journal"]] == [
            "listed 1 indexed function"
        ]
        # The finding reported before the crash survives the takeover.
        assert [finding.cwe_id for finding in outcome.findings] == ["CWE-95"]
        decisions = outcome.run["decisions"]
        assert [record["sequence"] for record in decisions][:2] == [1, 2]
        assert decisions[-1]["decision"] == "loop_completed"
        # The terminal checkpoint marks the investigation done for this job.
        latest = await checkpoints.latest(task_id)
        assert latest is not None and latest.state["completed"] is True
        await database.dispose()

    asyncio.run(scenario())


def test_completed_checkpoint_is_never_replayed(
    persistence_database_url: str, tmp_path: Any
) -> None:
    async def scenario() -> None:
        from vulnweaver_orchestrator import InMemoryCheckpointStore

        database = Database(DatabaseSettings(persistence_database_url))
        suffix, version_id = await seed(
            database,
            lambda vid: [source_function(f"pair-fn:{uuid4().hex}", vid, "src/app.py")],
        )
        task_id = f"task:{suffix}"
        job_id = f"job:audit:{suffix}"
        checkpoints = InMemoryCheckpointStore()
        state = _interrupted_checkpoint_state(
            job_id, f"agent-run:semantic-audit:{suffix}-agent", version_id
        )
        state["completed"] = True
        await checkpoints.save(task_id, AUDIT_CHECKPOINT_NODE, state, created_at=TIMESTAMP)

        planner = ScriptedPlanner([])
        agent = CodeAuditAgent(
            database,
            planner,
            LocalContentAddressedStore(tmp_path),
            checkpoint_store=checkpoints,
        )
        outcome = await agent.audit(
            task_id=task_id,
            job_id=job_id,
            attempt=2,
            run_id=f"agent-run:semantic-audit:{suffix}-retry",
            input_refs=(version_id,),
        )
        # No resumed findings or steps: the completed marker forces a fresh run.
        assert outcome.findings == ()
        assert all(step.step_id != "s1" for step in outcome.steps)
        await database.dispose()

    asyncio.run(scenario())
