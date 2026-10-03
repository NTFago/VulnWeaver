"""CR-04: the differential-behavior oracle behind auth and injection facts.

The trusted entrypoint digests every run's captured output; a crafted input
whose output differs from the control input and reproduces byte-for-byte on
replays is a supervisor-verified behavior difference. The worker maps that
observation onto typed ``POC_VERIFICATION_RESULT`` markers — never model
claims — and the review gate turns those markers into category facts.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
from typing import Any, cast
from uuid import uuid4

from vulnweaver_artifact_store import LocalContentAddressedStore
from vulnweaver_contracts import (
    EvidenceStrength,
    EvidenceType,
    Finding,
    FindingCategory,
    FindingStatus,
    JobStatus,
    Severity,
)
from vulnweaver_persistence import Database, DatabaseSettings
from vulnweaver_proof import (
    ExploitScriptGenerator,
    ProofExecutionService,
    ProofJobExecutor,
    load_execution_bundle_manifest,
)
from vulnweaver_proof.verifier import (
    differential_evidence_from_observation,
    observation_is_consistent,
    parse_observation,
)

from tests.persistence.factories import artifact, artifact_version, task
from tests.proof.test_auto_poc import (
    TIMESTAMP,
    FakePocModel,
    _enabled_project,
    _poc_job,
)

CRAFTED_DIGEST = "sha256:" + "1" * 64
CONTROL_DIGEST = "sha256:" + "2" * 64
CONSTRAINT = "admin session tokens must expire after fifteen minutes"


def _constraint_digest(text: str) -> str:
    import unicodedata

    normalized = unicodedata.normalize("NFKC", text).strip()
    return "sha256:" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _behavior_observation(
    finding_id: str,
    *,
    constraint_digest: str | None,
    differed: bool = True,
    replay_consistent: bool = True,
    forged_digests: bool = False,
) -> dict[str, object]:
    crafted = CRAFTED_DIGEST
    runs = [
        {
            "role": "control", "input_name": "0000", "exit_code": 0, "signal": None,
            "duration_millis": 3, "target_frames": False, "timed_out": False,
            "output_digest": CONTROL_DIGEST,
        },
        {
            "role": "trigger", "input_name": "0000", "exit_code": 0, "signal": None,
            "duration_millis": 8, "target_frames": False, "timed_out": False,
            "output_digest": crafted,
        },
    ]
    runs.extend(
        {
            "role": "replay", "input_name": "0000", "exit_code": 0, "signal": None,
            "duration_millis": 7, "target_frames": False, "timed_out": False,
            "output_digest": crafted if replay_consistent else CONTROL_DIGEST,
        }
        for _ in range(2)
    )
    return {
        "schema_version": "1.0.0",
        "id": "observation:" + "b" * 32,
        "kind": "proof_of_concept",
        "finding_id": finding_id,
        "verdict": "verified_behavior",
        "verdict_reasons": [
            "behavior_difference_observed", "control_input_clean", "replay_stable",
        ],
        "driver_digest": "sha256:" + "c" * 64,
        "target_binding": {
            "artifact_id": "artifact:test",
            "version_id": "artifact-version:test",
            "artifact_kind": "source_archive",
            "digest": "sha256:" + "d" * 64,
        },
        "inputs": [{"name": "inputs/0000", "digest": "sha256:" + "e" * 64, "size_bytes": 4}],
        "controls": [{"name": "controls/0000", "digest": "sha256:" + "f" * 64, "size_bytes": 4}],
        "runs": runs,
        "trigger_runs": 0,
        "replay_runs": 2,
        "untrusted_claims": None,
        "observed_behavior": {
            # Forged: the claimed crafted digest differs from what the trigger
            # run itself recorded, so the claim cannot follow from the runs.
            "crafted_output_digest": CONTROL_DIGEST if forged_digests else crafted,
            "control_output_digest": CONTROL_DIGEST,
            "differed": differed,
            "replay_consistent": replay_consistent,
        },
        "constraint_digest": constraint_digest,
        "verifier": {"name": "proof-entrypoint", "version": "2.1.0", "image_digest": None},
        "created_at": TIMESTAMP,
    }


def test_consistent_verified_behavior_observation_passes_checks() -> None:
    observation = parse_observation(_behavior_observation("finding:t", constraint_digest=None))
    assert observation_is_consistent(observation) is True


def test_forged_behavior_digest_is_inconsistent() -> None:
    """observed_behavior must match the digests the runs themselves recorded."""

    observation = parse_observation(
        _behavior_observation("finding:t", constraint_digest=None, forged_digests=True)
    )
    assert observation_is_consistent(observation) is False


def test_inconsistent_replay_claims_are_rejected() -> None:
    observation = parse_observation(
        _behavior_observation(
            "finding:t", constraint_digest=None, replay_consistent=False
        )
    )
    assert observation_is_consistent(observation) is False


def test_differential_evidence_for_bound_auth_constraint() -> None:
    evidence = differential_evidence_from_observation(
        cast(Any, _behavior_observation(
            "finding:t", constraint_digest=_constraint_digest(CONSTRAINT)
        )),
        evidence_id="evidence:diff",
        finding_category="auth_or_business_logic",
        finding_constraint_digest=_constraint_digest(CONSTRAINT),
        bundle_ref="cas://bundle",
        bundle_digest="sha256:" + "7" * 64,
        created_at=TIMESTAMP,
    )
    assert evidence is not None
    assert evidence["type"] is EvidenceType.POC_VERIFICATION_RESULT
    assert evidence["strength"] is EvidenceStrength.STRONG
    markers = evidence["replay_recipe"]["markers"]
    assert markers["constraint_digest"] == _constraint_digest(CONSTRAINT)
    assert "behavior_difference" in markers


def test_differential_evidence_requires_the_bound_constraint() -> None:
    """An unbound or mismatched constraint digests to no auth fact."""

    for observed, registered in (
        (None, _constraint_digest(CONSTRAINT)),
        (_constraint_digest(CONSTRAINT), None),
        (_constraint_digest(CONSTRAINT), _constraint_digest("a different constraint")),
    ):
        evidence = differential_evidence_from_observation(
            cast(Any, _behavior_observation("finding:t", constraint_digest=observed)),
            evidence_id="evidence:diff",
            finding_category="auth_or_business_logic",
            finding_constraint_digest=registered,
            bundle_ref="cas://bundle",
            bundle_digest="sha256:" + "7" * 64,
            created_at=TIMESTAMP,
        )
        assert evidence is None


def test_differential_evidence_for_injection_records_sink_reached() -> None:
    evidence = differential_evidence_from_observation(
        cast(Any, _behavior_observation("finding:t", constraint_digest=None)),
        evidence_id="evidence:diff",
        finding_category="injection",
        finding_constraint_digest=None,
        bundle_ref="cas://bundle",
        bundle_digest="sha256:" + "7" * 64,
        created_at=TIMESTAMP,
    )
    assert evidence is not None
    markers = evidence["replay_recipe"]["markers"]
    assert markers["sink_reached"] is True
    assert markers["source"] == "crafted_input"


def test_differential_evidence_is_refused_for_memory_corruption() -> None:
    """An output difference says nothing about memory safety."""

    evidence = differential_evidence_from_observation(
        cast(Any, _behavior_observation("finding:t", constraint_digest=None)),
        evidence_id="evidence:diff",
        finding_category="memory_corruption",
        finding_constraint_digest=None,
        bundle_ref="cas://bundle",
        bundle_digest="sha256:" + "7" * 64,
        created_at=TIMESTAMP,
    )
    assert evidence is None


# -- worker integration --------------------------------------------------------


class BehaviorSandbox:
    """Completes the tool run with a verified_behavior observation in CAS."""

    def __init__(
        self,
        store: LocalContentAddressedStore,
        observation: dict[str, object],
    ) -> None:
        self._store = store
        self._observation = observation
        self.calls = 0

    async def run(self, request: object, cancellation: object) -> dict[str, object]:
        self.calls += 1
        sandbox_request = cast(dict[str, object], request)
        manifest, _ = load_execution_bundle_manifest(
            self._store, str(sandbox_request["input_ref"])
        )
        observation = dict(self._observation)
        observation["driver_digest"] = manifest["driver"]["digest"]
        observation["target_binding"] = dict(manifest["target_binding"])
        observation["inputs"] = [dict(member) for member in manifest.get("inputs") or []]
        observation["controls"] = [dict(member) for member in manifest.get("controls") or []]
        observation["runs"] = [
            {**run, "input_name": str(run["input_name"])} for run in observation["runs"]
        ]
        stored = self._store.put_stream(
            io.BytesIO(json.dumps(observation).encode("utf-8")), max_bytes=1024 * 1024
        )
        return cast(
            dict[str, object],
            {
                "schema_version": "1.0.0",
                "request_id": "sandbox-request:test",
                "status": "succeeded",
                "exit_code": 0,
                "stdout_ref": None,
                "stderr_ref": None,
                "outputs": [
                    {
                        "path": "execution-report.json",
                        "object_ref": stored.object_ref,
                        "digest": stored.digest,
                        "size_bytes": stored.size_bytes,
                    }
                ],
                "resource_usage": {
                    "duration_millis": 10,
                    "cpu_millis": 5,
                    "memory_bytes": 1024,
                    "output_bytes": 0,
                },
                "failure": None,
            },
        )


async def _seed_auth_finding(
    database: Database,
    suffix: str,
    store: LocalContentAddressedStore,
) -> tuple[str, str, str]:
    """Auth finding whose audit report registers one constraint."""

    project_id = f"project:{suffix}"
    version_id = f"artifact-version:{suffix}"
    task_id = f"task:{suffix}"
    version = dict(artifact_version(version_id, artifact_id=f"artifact:{suffix}"))
    target = store.put_stream(
        io.BytesIO(b"def parse(value):\n    return value\n"), max_bytes=1024 * 1024
    )
    version["digest"] = target.digest
    version["object_ref"] = target.object_ref
    async with database.transaction() as repositories:
        await repositories.projects.add(cast(Any, _enabled_project(project_id)))
        await repositories.artifacts.add(
            artifact(f"artifact:{suffix}", project_id=project_id, current_version_id=version_id)
        )
        await repositories.artifacts.add_version(cast(Any, version))
        await repositories.tasks.create(
            task(
                task_id,
                project_id=project_id,
                artifact_version_ids=[version_id],
                idempotency_key=f"task-key:{suffix}",
            )
        )
        finding = cast(
            Finding,
            {
                "schema_version": "1.0.0",
                "id": f"finding:{suffix}",
                "task_id": task_id,
                "category": FindingCategory.AUTH_OR_BUSINESS_LOGIC,
                "cwe_id": "CWE-613",
                "title": "session token never expires",
                "severity": Severity.HIGH,
                "confidence": 0.6,
                "location": {
                    "artifact_version_id": version_id,
                    "path": "auth.py",
                    "start_line": 5,
                    "start_column": 1,
                    "end_line": 9,
                    "end_column": 2,
                },
                "dataflow": [],
                "call_path": [],
                "status": FindingStatus.CANDIDATE,
                "evidence_ids": [],
                "review_ids": [],
                "poc_ids": [],
                "fix_suggestion": "enforce expiry",
                "created_at": TIMESTAMP,
            },
        )
        await repositories.findings.create(finding)
        report = {
            "schema_version": "1.0.0",
            "report": {
                "findings": [
                    {
                        "cwe_id": "CWE-613",
                        "title": "session token never expires",
                        "path": "auth.py",
                        "start_line": 5,
                        "constraint": CONSTRAINT,
                    }
                ]
            },
        }
        stored = store.put_stream(
            io.BytesIO(json.dumps(report).encode("utf-8")), max_bytes=1024 * 1024
        )
        evidence = {
            "schema_version": "1.0.0",
            "id": f"evidence:audit:{suffix}",
            "type": "model_explanation",
            "strength": "contextual",
            "artifact_ref": stored.object_ref,
            "digest": stored.digest,
            "tool": {"name": "vulnweaver-semantic-audit", "version": "1.0.0", "image_digest": None},
            "input_ref": stored.object_ref,
            "command_hash": None,
            "exit_code": None,
            "stdout_ref": None,
            "stderr_ref": None,
            "replay_recipe": {"kind": "semantic_model_audit", "reproducible": False},
            "created_at": TIMESTAMP,
        }
        await repositories.evidence.create(cast(Any, evidence))
        await repositories.findings.link_evidence(
            {
                "schema_version": "1.0.0",
                "finding_id": f"finding:{suffix}",
                "evidence_id": f"evidence:audit:{suffix}",
                "relation": "supports",
                "weight": 0.4,
                "created_by": "test",
                "created_at": TIMESTAMP,
            }
        )
    return task_id, f"finding:{suffix}", _constraint_digest(CONSTRAINT)


async def _seed_injection_finding(
    database: Database,
    suffix: str,
    store: LocalContentAddressedStore,
) -> tuple[str, str]:
    """Injection finding over an eval-shaped target, without audit constraint."""

    project_id = f"project:{suffix}"
    version_id = f"artifact-version:{suffix}"
    task_id = f"task:{suffix}"
    version = dict(artifact_version(version_id, artifact_id=f"artifact:{suffix}"))
    target = store.put_stream(
        io.BytesIO(b"def parse(value):\n    return eval(value)\n"), max_bytes=1024 * 1024
    )
    version["digest"] = target.digest
    version["object_ref"] = target.object_ref
    async with database.transaction() as repositories:
        await repositories.projects.add(cast(Any, _enabled_project(project_id)))
        await repositories.artifacts.add(
            artifact(f"artifact:{suffix}", project_id=project_id, current_version_id=version_id)
        )
        await repositories.artifacts.add_version(cast(Any, version))
        await repositories.tasks.create(
            task(
                task_id,
                project_id=project_id,
                artifact_version_ids=[version_id],
                idempotency_key=f"task-key:{suffix}",
            )
        )
        finding = cast(
            Finding,
            {
                "schema_version": "1.0.0",
                "id": f"finding:{suffix}",
                "task_id": task_id,
                "category": FindingCategory.INJECTION,
                "cwe_id": "CWE-95",
                "title": "eval on request data",
                "severity": Severity.HIGH,
                "confidence": 0.6,
                "location": {
                    "artifact_version_id": version_id,
                    "path": "app.py",
                    "start_line": 2,
                    "start_column": 1,
                    "end_line": 2,
                    "end_column": 24,
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
        await repositories.findings.create(finding)
    return task_id, f"finding:{suffix}"


def test_differential_run_for_injection_carries_protection_enumeration(
    persistence_database_url: str, tmp_path: object
) -> None:
    """The injection marker list comes from the control-plane AST scan (CR-04)."""

    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        suffix = uuid4().hex
        store = LocalContentAddressedStore(cast(Any, tmp_path))
        task_id, finding_id = await _seed_injection_finding(database, suffix, store)
        observation = _behavior_observation(finding_id, constraint_digest=None)
        executor = ProofJobExecutor(
            database,
            ProofExecutionService(
                BehaviorSandbox(store, observation),
                tool_name="proof-tool",
                tool_version="1.0.0",
                store=store,
            ),
            store=store,
            script_generator=ExploitScriptGenerator(database, FakePocModel(), store),
        )
        try:
            result = await executor.execute(_poc_job(task_id, finding_id, suffix), asyncio.Event())
            assert result["status"] is JobStatus.SUCCEEDED, result["failure"]
            assert len(result["evidence_ids"]) == 2
            async with database.transaction() as repositories:
                records = [
                    await repositories.evidence.get(evidence_id)
                    for evidence_id in result["evidence_ids"]
                ]
            strong = next(
                record
                for record in records
                if record["type"] == "poc_verification_result"
            )
            markers = strong["replay_recipe"]["markers"]
            assert markers["sink_reached"] is True
            protections = markers["protections_observed"]
            assert isinstance(protections, list) and protections
            # The enumeration documents the eval sink the sandbox actually ran.
            assert any(
                entry.startswith("dangerous_sink:eval@") for entry in protections
            )
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_differential_run_writes_strong_poc_verification_evidence(
    persistence_database_url: str, tmp_path: object
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        suffix = uuid4().hex
        store = LocalContentAddressedStore(cast(Any, tmp_path))
        task_id, finding_id, constraint_digest = await _seed_auth_finding(
            database, suffix, store
        )
        observation = _behavior_observation(finding_id, constraint_digest=constraint_digest)
        executor = ProofJobExecutor(
            database,
            ProofExecutionService(
                BehaviorSandbox(store, observation),
                tool_name="proof-tool",
                tool_version="1.0.0",
                store=store,
            ),
            store=store,
            script_generator=ExploitScriptGenerator(database, FakePocModel(), store),
        )
        try:
            result = await executor.execute(_poc_job(task_id, finding_id, suffix), asyncio.Event())
            assert result["status"] is JobStatus.SUCCEEDED, result["failure"]
            assert len(result["evidence_ids"]) == 2
            async with database.transaction() as repositories:
                records = [
                    await repositories.evidence.get(evidence_id)
                    for evidence_id in result["evidence_ids"]
                ]
            types = sorted(record["type"] for record in records)
            assert types == ["poc_verification_result", "verification_observation"]
            strong = next(
                record
                for record in records
                if record["type"] == "poc_verification_result"
            )
            assert strong["strength"] == "strong"
            markers = strong["replay_recipe"]["markers"]
            assert markers["constraint_digest"] == constraint_digest
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_differential_run_without_constraint_binding_stays_weak(
    persistence_database_url: str, tmp_path: object
) -> None:
    """A behavior difference without the bound constraint yields no auth fact."""

    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        suffix = uuid4().hex
        store = LocalContentAddressedStore(cast(Any, tmp_path))
        task_id, finding_id, _digest = await _seed_auth_finding(database, suffix, store)
        observation = _behavior_observation(finding_id, constraint_digest=None)
        executor = ProofJobExecutor(
            database,
            ProofExecutionService(
                BehaviorSandbox(store, observation),
                tool_name="proof-tool",
                tool_version="1.0.0",
                store=store,
            ),
            store=store,
            script_generator=ExploitScriptGenerator(database, FakePocModel(), store),
        )
        try:
            result = await executor.execute(_poc_job(task_id, finding_id, suffix), asyncio.Event())
            assert result["status"] is JobStatus.SUCCEEDED, result["failure"]
            # Only the diagnostic observation evidence; no strong markers.
            assert len(result["evidence_ids"]) == 1
            async with database.transaction() as repositories:
                record = await repositories.evidence.get(result["evidence_ids"][0])
            assert record["type"] == "verification_observation"
        finally:
            await database.dispose()

    asyncio.run(scenario())
