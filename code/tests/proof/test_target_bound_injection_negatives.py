"""Opt-in RG-01/RG-02 negatives against a live Sandbox Runner (fixed targets).

These cases document, end to end on the real runner, that the residual
in-process forgery surfaces do NOT translate into injection confirmation
facts:

* exit-20 forgery — the target prints crafted-dependent output and calls
  ``os._exit(20)``: the forgery lands in the observation (sink_fired True),
  the worker records the markers, and the demoted fact derivation still
  yields nothing beyond a minimal reproduction.
* profiler suppression — the target clears the profiler before the sink
  fires: the reach claim silently disappears (conservative direction), and
  the evidence carries no sink_reached marker.
* constant sink — a lexicon sink fires on every run while the output
  difference comes from elsewhere: same demotion applies.

All targets are harmless fixed strings; the assertions pin the trust
boundary recorded in ADR-036 and code-review-2026-10-04-gates.md.
"""

from __future__ import annotations

import asyncio
import io
import os
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

import pytest
from vulnweaver_artifact_store import LocalContentAddressedStore
from vulnweaver_contracts import (
    EvidenceRelation,
    Finding,
    FindingCategory,
    FindingStatus,
    Job,
    JobKind,
    JobStatus,
    RunStatus,
    Severity,
)
from vulnweaver_model_gateway import ModelCallResult
from vulnweaver_orchestrator.reviews import (
    ReviewEvidenceFact,
    ReviewFactContext,
    derive_established_facts,
)
from vulnweaver_persistence import Database, DatabaseSettings
from vulnweaver_proof import (
    ExploitScriptGenerator,
    ProofExecutionService,
    ProofJobExecutor,
    SandboxRunnerClient,
)

from tests.persistence.factories import artifact, artifact_version, job, project, task

RUNNER_URL = os.environ.get("SANDBOX_RUNNER_URL", "").strip()
RUNNER_TOKEN = os.environ.get("SANDBOX_RUNNER_TOKEN", "").strip()
CAS_ROOT = os.environ.get("VULNWEAVER_SHARED_CAS_ROOT", "/var/lib/vulnweaver/artifacts").strip()

pytestmark = pytest.mark.skipif(
    not RUNNER_URL or not Path(CAS_ROOT).is_dir(),
    reason="SANDBOX_RUNNER_URL and a shared VULNWEAVER_SHARED_CAS_ROOT are required",
)

TIMESTAMP = "2026-10-04T08:00:00Z"
CRAFTED = "crafted-payload"
CONTROL = "benign-payload"

# The target forges the sink exit code only for the crafted input and makes
# the outputs diverge — everything the supervisor trusts, all forged in-process.
EXIT20_FORGERY = (
    "import os\n"
    "def parse(value):\n"
    "    if 'crafted' in value:\n"
    "        print('ADMIN GRANTED', flush=True)\n"
    "        os._exit(20)\n"
    "    return 'denied'\n"
)

# The target disables the profiler before the sink fires: the observation
# goes blind (a false negative — the conservative direction).
PROFILER_SUPPRESSION = (
    "import sys\n"
    "def parse(value):\n"
    "    sys.setprofile(None)\n"
    "    return eval('1+1')\n"
)

# The sink fires on every run with a constant argument while the output
# difference comes from the input branch — no input ever reaches the sink.
CONSTANT_SINK = (
    "def parse(value):\n"
    "    eval('1+1')\n"
    "    return 'A' if 'crafted' in value else 'B'\n"
)


def _client(timeout_seconds: float) -> SandboxRunnerClient:
    return SandboxRunnerClient(
        RUNNER_URL,
        timeout_seconds=timeout_seconds,
        bearer_token=RUNNER_TOKEN or None,
    )


class FixedDriverModel:
    """Returns one fixed invocation plus its crafted and control inputs."""

    def __init__(self, crafted: str = CRAFTED, control: str = CONTROL) -> None:
        self._output = {
            "schema_version": "1.0.0",
            "driver": {"target_callable": "parse", "input_mode": "text"},
            "crafted_input": crafted,
            "control_input": control,
            "rationale": "RG negative acceptance driver",
        }

    async def complete_structured(self, **kwargs: object) -> ModelCallResult:
        run = {
            "schema_version": "1.0.0",
            "id": "agent-run:rg-negative",
            "task_id": "task:rg-negative",
            "status": RunStatus.SUCCEEDED,
            "model": "planning/rg-negative",
            "prompt_hash": "sha256:" + "a" * 64,
            "input_refs": [],
            "decisions": [],
            "token_usage": {"input_tokens": 5, "output_tokens": 5},
            "failure": None,
            "created_at": TIMESTAMP,
            "updated_at": TIMESTAMP,
        }
        return ModelCallResult(self._output, run, None, "endpoint-1")  # type: ignore[arg-type]


async def _seed_injection(
    database: Database,
    store: LocalContentAddressedStore,
    *,
    target_source: str,
) -> tuple[str, str]:
    suffix = uuid4().hex
    project_id = f"project:rg-{suffix}"
    version_id = f"artifact-version:rg-{suffix}"
    task_id = f"task:rg-{suffix}"
    stored = store.put_stream(
        io.BytesIO(target_source.encode("utf-8")), max_bytes=1024 * 1024
    )
    async with database.transaction() as repositories:
        seeded = dict(project(project_id))
        seeded["exploit_validation_enabled"] = True
        await repositories.projects.add(cast(Any, seeded))
        await repositories.artifacts.add(
            artifact(f"artifact:rg-{suffix}", project_id=project_id, current_version_id=version_id)
        )
        version = dict(artifact_version(version_id, artifact_id=f"artifact:rg-{suffix}"))
        version["digest"] = stored.digest
        version["object_ref"] = stored.object_ref
        await repositories.artifacts.add_version(cast(Any, version))
        await repositories.tasks.create(
            task(
                task_id,
                project_id=project_id,
                artifact_version_ids=[version_id],
                idempotency_key=f"task-key:rg-{suffix}",
            )
        )
        await repositories.findings.create(
            cast(
                Finding,
                {
                    "schema_version": "1.0.0",
                    "id": f"finding:rg-{suffix}",
                    "task_id": task_id,
                    "category": FindingCategory.INJECTION,
                    "cwe_id": "CWE-95",
                    "title": "eval on request data",
                    "severity": Severity.HIGH,
                    "confidence": 0.6,
                    "location": {
                        "artifact_version_id": version_id,
                        "path": "target.py",
                        "start_line": 2,
                        "start_column": 1,
                        "end_line": 6,
                        "end_column": 20,
                    },
                    "dataflow": [],
                    "call_path": [],
                    "status": FindingStatus.CANDIDATE,
                    "evidence_ids": [],
                    "review_ids": [],
                    "poc_ids": [],
                    "fix_suggestion": "remove eval",
                    "created_at": TIMESTAMP,
                },
            )
        )
    return task_id, f"finding:rg-{suffix}"


def _run_case(
    database_url: str,
    store: LocalContentAddressedStore,
    task_id: str,
    finding_id: str,
) -> Any:
    database = Database(DatabaseSettings(database_url))
    service = ProofExecutionService(
        _client(150.0),
        tool_name="proof-tool",
        tool_version="1.0.0",
        store=store,
    )
    executor = ProofJobExecutor(
        database,
        service,
        store=store,
        script_generator=ExploitScriptGenerator(database, FixedDriverModel(), store),
    )
    suffix = uuid4().hex
    proof_job = job(
        f"job:rg-poc:{suffix}",
        task_id=task_id,
        idempotency_key=f"rg-poc:{suffix}",
        kind=JobKind.PROOF,
    )
    proof_job["arguments"] = {
        "poc_verification": {
            "finding_id": finding_id,
            "image_digest": _service_digest(store),
        }
    }
    return asyncio.run(executor.execute(cast(Job, proof_job), asyncio.Event()))


_DIGEST_CACHE: dict[str, str] = {}


def _service_digest(store: LocalContentAddressedStore) -> str:
    if "digest" not in _DIGEST_CACHE:

        async def fetch() -> str:
            client = _client(30.0)
            digest = await client.tool_digest("proof-tool", "1.0.0")
            if digest is None:
                raise RuntimeError("proof-tool is not registered on the runner")
            return digest

        _DIGEST_CACHE["digest"] = asyncio.run(fetch())
    return _DIGEST_CACHE["digest"]


async def _load_evidence(database_url: str, finding_id: str, evidence_id: str) -> Any:
    database = Database(DatabaseSettings(database_url))
    async with database.transaction() as repositories:
        record = await repositories.evidence.get(evidence_id)
    await database.dispose()
    return record


def _assert_no_confirmation_facts_derive(evidence: Any) -> None:
    """RG-01/RG-02: whatever the markers claim, only reproduction derives."""

    fact = ReviewEvidenceFact(
        evidence_id=evidence["id"],
        relation=EvidenceRelation.SUPPORTS,
        evidence_type=evidence["type"],
        strength=evidence["strength"],
        artifact_ref=evidence["artifact_ref"],
        digest=evidence["digest"],
        tool=evidence["tool"],
        command_hash=evidence["command_hash"],
        exit_code=evidence["exit_code"],
        replay_facts=evidence["replay_recipe"],
    )
    context = ReviewFactContext(
        finding_id="finding:rg",
        category=FindingCategory.INJECTION,
        cwe_id="CWE-95",
        location={},
        current_status=FindingStatus.CANDIDATE,
        evidence=(fact,),
    )
    derived = derive_established_facts(context)
    assert derived == frozenset({"minimal_reproduction"})


@pytest.mark.parametrize(
    ("label", "target_source"),
    [
        ("exit20-forgery", EXIT20_FORGERY),
        ("constant-sink", CONSTANT_SINK),
    ],
)
def test_real_runner_injection_forgery_lands_but_derives_nothing(
    persistence_database_url: str, label: str, target_source: str
) -> None:
    store = LocalContentAddressedStore(CAS_ROOT)

    async def seed() -> tuple[str, str]:
        database = Database(DatabaseSettings(persistence_database_url))
        seeded = await _seed_injection(database, store, target_source=target_source)
        await database.dispose()
        return seeded

    task_id, finding_id = asyncio.run(seed())
    result = _run_case(persistence_database_url, store, task_id, finding_id)

    assert result["status"] is JobStatus.SUCCEEDED, (label, result["failure"])
    # The behavior oracle fires (the outputs genuinely differ) and the
    # differential evidence is persisted with its diagnostic markers.
    assert len(result["evidence_ids"]) == 2, label

    async def verify() -> tuple[list[Any], Any]:
        database = Database(DatabaseSettings(persistence_database_url))
        async with database.transaction() as repositories:
            pocs = await repositories.pocs.list_for_finding(finding_id)
            finding = await repositories.findings.get(finding_id)
            records = [
                await repositories.evidence.get(evidence_id)
                for evidence_id in result["evidence_ids"]
            ]
        await database.dispose()
        return pocs, (finding, records)

    pocs, (finding, records) = asyncio.run(verify())
    assert pocs[0]["result"] == "inconclusive", label
    assert pocs[0]["status"] == "completed", label
    assert finding["status"] == FindingStatus.CANDIDATE, label

    differential = next(
        record for record in records if record["type"] == "poc_verification_result"
    )
    markers = differential["replay_recipe"]["markers"]
    # The forgery is visible in the markers — and derives nothing.
    assert markers.get("sink_reached") is True, label
    _assert_no_confirmation_facts_derive(differential)


def test_real_runner_profiler_suppression_yields_no_reach_claim(
    persistence_database_url: str,
) -> None:
    store = LocalContentAddressedStore(CAS_ROOT)

    async def seed() -> tuple[str, str]:
        database = Database(DatabaseSettings(persistence_database_url))
        seeded = await _seed_injection(
            database, store, target_source=PROFILER_SUPPRESSION
        )
        await database.dispose()
        return seeded

    task_id, finding_id = asyncio.run(seed())
    result = _run_case(persistence_database_url, store, task_id, finding_id)

    assert result["status"] is JobStatus.SUCCEEDED, result["failure"]
    # The behavior difference exists (constant output actually) — but reach
    # must not be claimed because the observation was blinded.

    async def verify() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        async with database.transaction() as repositories:
            pocs = await repositories.pocs.list_for_finding(finding_id)
            relations = await repositories.findings.list_evidence_relations(finding_id)
        assert pocs[0]["result"] in {"inconclusive", "not_exploitable_under_environment"}
        for relation in relations:
            evidence = await repositories.evidence.get(relation["evidence_id"])
            if evidence["type"] == "poc_verification_result":
                markers = evidence["replay_recipe"]["markers"]
                assert "sink_reached" not in markers
        await database.dispose()

    asyncio.run(verify())
