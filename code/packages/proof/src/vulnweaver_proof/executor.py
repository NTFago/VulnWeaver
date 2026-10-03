"""Build and execute proof requests without giving callers command access."""

from __future__ import annotations

import asyncio
import io
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol, cast

from vulnweaver_artifact_store import ArtifactStore, ArtifactStoreError
from vulnweaver_contracts import (
    SCHEMA_VERSION,
    Artifact,
    ArtifactKind,
    ArtifactVersion,
    EvidenceRelation,
    FailureKind,
    Finding,
    FindingEvidence,
    FindingStatus,
    Job,
    JobKind,
    JobStatus,
    Poc,
    PocKind,
    PocResult,
    PocStatus,
    ProofRequest,
    SandboxRequest,
    SandboxResult,
    SandboxStatus,
    SchemaVersion,
    StructuredFailure,
    TargetBinding,
    ToolIdentity,
    VerificationObservation,
    VerificationOutcome,
    WorkerResult,
    validate_contract,
)
from vulnweaver_domain import evaluate_exploit_eligibility
from vulnweaver_persistence import Database, EntityNotFound, Repositories

from .auto_exploit import (
    POC_VERIFICATION_BASELINE,
    AutoExploitError,
    ExploitScriptGenerator,
    GeneratedExploit,
    stable_id,
)
from .bundle import ExecutionBundleError, build_execution_bundle
from .validation import ScriptRefOwnershipError, ensure_script_ref_belongs_to_project
from .verifier import (
    REPORT_FILE_NAME,
    ObservationError,
    evidence_from_observation,
    parse_observation,
    poc_result_from_observation,
)


class ProofSandbox(Protocol):
    async def run(self, request: SandboxRequest, cancellation: asyncio.Event) -> SandboxResult: ...


class ProofExecutionError(ValueError):
    """Raised when a proof request is malformed or its tool binding is unsafe."""


@dataclass(frozen=True, slots=True)
class ProofRun:
    """One executed proof request plus its trusted verification observation."""

    poc: Poc
    observation: VerificationObservation | None
    sandbox_result: SandboxResult


class ProofJobExecutor:
    """Adapt the proof service to the durable Worker execution contract."""

    def __init__(
        self,
        database: Database,
        service: ProofExecutionService,
        *,
        store: ArtifactStore | None = None,
        script_generator: ExploitScriptGenerator | None = None,
    ) -> None:
        self._database = database
        self._service = service
        self._store = store
        self._script_generator = script_generator

    async def execute(self, job: Job, cancellation: asyncio.Event) -> WorkerResult:
        if job["kind"] not in {JobKind.PROOF, JobKind.EXPLOIT}:
            return _worker_failure(job, "proof.invalid_job_kind", FailureKind.VALIDATION)
        arguments = job.get("arguments")
        raw_request = arguments.get("proof_request") if isinstance(arguments, dict) else None
        raw_auto = arguments.get("auto_exploit") if isinstance(arguments, dict) else None
        raw_poc = (
            arguments.get(POC_VERIFICATION_BASELINE) if isinstance(arguments, dict) else None
        )
        kind = PocKind.EXPLOIT if job["kind"] is JobKind.EXPLOIT else PocKind.PROOF_OF_CONCEPT
        produced_version_ids: list[str] = []
        try:
            if isinstance(raw_auto, dict):
                if job["kind"] is not JobKind.EXPLOIT:
                    return _worker_failure(
                        job, "proof.auto_requires_exploit_kind", FailureKind.VALIDATION
                    )
                request, produced = await self._prepare_auto_request(
                    job, cast(dict[str, object], raw_auto)
                )
                produced_version_ids.append(produced)
            elif isinstance(raw_poc, dict):
                if job["kind"] is not JobKind.PROOF:
                    return _worker_failure(
                        job, "proof.poc_verification_requires_proof_kind", FailureKind.VALIDATION
                    )
                request, produced = await self._prepare_poc_verification_request(
                    job, cast(dict[str, object], raw_poc)
                )
                produced_version_ids.append(produced)
            else:
                if not isinstance(raw_request, dict):
                    return _worker_failure(job, "proof.request_required", FailureKind.VALIDATION)
                request = cast(ProofRequest, raw_request)
            # The sandbox call must stay outside any database transaction so a
            # slow runner cannot pin a pooled connection for the whole timeout.
            async with self._database.transaction() as repositories:
                finding = await repositories.findings.get(request["finding_id"])
                expected_target_binding, _, _ = await self._target_binding(
                    repositories, finding
                )
                finding_status = finding["status"]
                task = await repositories.tasks.get(finding["task_id"])
                project = await repositories.projects.get(task["project_id"])
                if not isinstance(raw_auto, dict) and not isinstance(raw_poc, dict):
                    await ensure_script_ref_belongs_to_project(
                        repositories, script_ref=request["script_ref"], project_id=project["id"]
                    )
                exploit_validation_enabled = project["exploit_validation_enabled"]
            run = await self._service.run(
                request,
                finding_status=finding_status,
                exploit_validation_enabled=exploit_validation_enabled,
                cancellation=cancellation,
                kind=kind,
                expected_target_binding=expected_target_binding,
            )
            poc = run.poc
            async with self._database.transaction() as repositories:
                await repositories.pocs.create(poc)
            evidence_ids = await self._persist_observation_evidence(
                job, finding, request, run
            )
        except ScriptRefOwnershipError as error:
            return _worker_failure(
                job, "proof.script_ref_outside_project", FailureKind.POLICY, str(error)
            )
        except AutoExploitError as error:
            return _worker_failure(job, error.code, error.kind, error.code.replace("_", " "))
        except (ProofExecutionError, ExecutionBundleError, ObservationError) as error:
            return _worker_failure(job, "proof.invalid_request", FailureKind.VALIDATION, str(error))
        except (TypeError, ValueError) as error:
            return _worker_failure(job, "proof.invalid_request", FailureKind.VALIDATION, str(error))
        status = JobStatus.CANCELLED if poc["status"] is PocStatus.CANCELLED else (
            JobStatus.SUCCEEDED if poc["status"] is PocStatus.COMPLETED else JobStatus.FAILED
        )
        return WorkerResult(
            schema_version=SchemaVersion.VALUE_1_0_0,
            job_id=job["id"],
            status=status,
            produced_artifact_version_ids=produced_version_ids,
            evidence_ids=evidence_ids,
            failure=None if status is not JobStatus.FAILED else StructuredFailure(
                code=f"proof.{poc['result'] or 'failed'}",
                kind=(
                    FailureKind.POLICY
                    if poc["result"] is PocResult.POLICY_DENIED
                    else FailureKind.TOOL
                ),
                message="proof execution did not complete successfully",
                retryable=False,
                details={},
            ),
        )

    async def _persist_observation_evidence(
        self,
        job: Job,
        finding: Finding,
        request: ProofRequest,
        run: ProofRun,
    ) -> list[str]:
        """Record STRONG evidence only for independently verified triggers."""

        observation = run.observation
        if observation is None:
            return []
        if str(observation["verdict"]) != VerificationOutcome.VERIFIED_TRIGGER:
            return []
        assert self._store is not None  # guarded by _prepare bundle construction
        evidence = evidence_from_observation(
            observation,
            evidence_id=stable_id("evidence", "verification-observation", job["id"]),
            bundle_ref=request["script_ref"],
            bundle_digest=self._store.verify(request["script_ref"]).digest,
            stdout_ref=run.sandbox_result["stdout_ref"],
            stderr_ref=run.sandbox_result["stderr_ref"],
            created_at=datetime.now(UTC).isoformat(),
        )
        async with self._database.transaction() as repositories:
            await repositories.evidence.create(evidence)
            await repositories.findings.link_evidence(
                FindingEvidence(
                    schema_version=SchemaVersion.VALUE_1_0_0,
                    finding_id=finding["id"],
                    evidence_id=evidence["id"],
                    relation=EvidenceRelation.SUPPORTS,
                    weight=1.0,
                    created_by="vulnweaver-proof-verifier",
                    created_at=evidence["created_at"],
                )
            )
        return [evidence["id"]]

    async def _target_binding(
        self, repositories: Repositories, finding: Finding
    ) -> tuple[TargetBinding, str, Artifact]:
        """Resolve the exact sample version the finding is anchored to."""

        version = await repositories.artifacts.get_version(
            finding["location"]["artifact_version_id"]
        )
        artifact = await repositories.artifacts.get(version["artifact_id"])
        binding = cast(
            TargetBinding,
            {
                "artifact_id": artifact["id"],
                "version_id": version["id"],
                "artifact_kind": artifact["kind"],
                "digest": version["digest"],
            },
        )
        return binding, version["object_ref"], artifact

    async def _build_and_register_bundle(
        self,
        job: Job,
        finding: Finding,
        generated: GeneratedExploit,
    ) -> tuple[str, str]:
        """Pack driver/target/inputs into one bundle and register it as DERIVED."""

        if self._store is None:
            raise AutoExploitError("proof.store_unavailable", FailureKind.DEPENDENCY)
        async with self._database.transaction() as repositories:
            binding, target_ref, artifact = await self._target_binding(repositories, finding)
        bundle = await asyncio.to_thread(
            build_execution_bundle,
            self._store,
            bundle_id=f"execution-bundle:{job['id']}",
            finding_id=finding["id"],
            driver_ref=generated.script_ref,
            target_binding=binding,
            target_ref=target_ref,
            input_refs=[generated.crafted_input_ref],
            control_refs=[generated.control_input_ref],
            created_at=datetime.now(UTC).isoformat(),
        )
        artifact_id = stable_id("artifact", "execution-bundle", job["id"])
        version_id = stable_id(
            "artifact-version", "execution-bundle", job["id"], bundle.stored.digest
        )
        async with self._database.transaction() as repositories:
            try:
                existing = await repositories.artifacts.get(artifact_id)
            except EntityNotFound:
                await repositories.artifacts.add(
                    Artifact(
                        schema_version=SchemaVersion.VALUE_1_0_0,
                        id=artifact_id,
                        project_id=artifact["project_id"],
                        kind=ArtifactKind.DERIVED,
                        current_version_id=version_id,
                        created_at=job["updated_at"],
                    )
                )
            else:
                if (existing["kind"] is not ArtifactKind.DERIVED
                        or existing["project_id"] != artifact["project_id"]):
                    raise AutoExploitError("proof.bundle_artifact_conflict", FailureKind.INTERNAL)
            version = cast(
                ArtifactVersion,
                {
                    "schema_version": SchemaVersion.VALUE_1_0_0,
                    "id": version_id,
                    "artifact_id": artifact_id,
                    "digest": bundle.stored.digest,
                    "object_ref": bundle.stored.object_ref,
                    # The bundle's parent is the analyzed sample version it is
                    # bound to; the driver lineage lives in generation_config.
                    "parent_version_id": binding["version_id"],
                    "produced_by": _producer_identity(),
                    "generation_config": {
                        "kind": "execution_bundle",
                        "driver_version_id": generated.script_version_id,
                        "driver_digest": bundle.manifest["driver"]["digest"],
                        "target_version_id": binding["version_id"],
                        "inputs": [
                            {"name": member["name"], "digest": member["digest"]}
                            for member in bundle.manifest.get("inputs") or ()
                        ],
                        "controls": [
                            {"name": member["name"], "digest": member["digest"]}
                            for member in bundle.manifest.get("controls") or ()
                        ],
                    },
                    "created_at": job["updated_at"],
                },
            )
            await repositories.artifacts.add_version(version)
        return bundle.stored.object_ref, version_id

    async def _prepare_poc_verification_request(
        self,
        job: Job,
        poc: dict[str, object],
    ) -> tuple[ProofRequest, str]:
        """Validate candidate-stage policy, generate the driver, build the bundle."""

        finding_id = poc.get("finding_id")
        image_digest = poc.get("image_digest")
        if not isinstance(finding_id, str) or not finding_id:
            raise AutoExploitError("poc_verification.finding_id_required", FailureKind.VALIDATION)
        if not isinstance(image_digest, str) or not image_digest.startswith("sha256:"):
            raise AutoExploitError("poc_verification.image_digest_required", FailureKind.VALIDATION)
        if self._script_generator is None:
            raise AutoExploitError("poc_verification.model_unconfigured", FailureKind.DEPENDENCY)
        async with self._database.transaction() as repositories:
            finding = await repositories.findings.get(finding_id)
            task = await repositories.tasks.get(finding["task_id"])
            project = await repositories.projects.get(task["project_id"])
            if (
                finding["status"] is not FindingStatus.CANDIDATE
                or not project["exploit_validation_enabled"]
            ):
                raise AutoExploitError("poc_verification.policy_denied", FailureKind.POLICY)
            permission_mode = project["permission_mode"]
        generated = await self._script_generator.generate(
            job, finding_id, baseline=POC_VERIFICATION_BASELINE
        )
        bundle_ref, bundle_version_id = await self._build_and_register_bundle(
            job, finding, generated
        )
        budget = job["resource_budget"]
        return (
            cast(
                ProofRequest,
                {
                    "schema_version": SchemaVersion.VALUE_1_0_0,
                    "id": f"poc:{job['id']}",
                    "job_id": job["id"],
                    "finding_id": finding_id,
                    # script_ref carries the target-bound ExecutionBundle.
                    "script_ref": bundle_ref,
                    "image_digest": image_digest,
                    "permission_mode": permission_mode,
                    "resource_budget": dict(budget),
                    "timeout_seconds": int(budget["timeout_seconds"]),
                },
            ),
            bundle_version_id,
        )

    async def _prepare_auto_request(
        self,
        job: Job,
        auto: dict[str, object],
    ) -> tuple[ProofRequest, str]:
        """Validate policy, generate and register the driver, build the bundle."""

        finding_id = auto.get("finding_id")
        image_digest = auto.get("image_digest")
        if not isinstance(finding_id, str) or not finding_id:
            raise AutoExploitError("auto_exploit.finding_id_required", FailureKind.VALIDATION)
        if not isinstance(image_digest, str) or not image_digest.startswith("sha256:"):
            raise AutoExploitError("auto_exploit.image_digest_required", FailureKind.VALIDATION)
        if self._script_generator is None:
            raise AutoExploitError("auto_exploit.model_unconfigured", FailureKind.DEPENDENCY)
        async with self._database.transaction() as repositories:
            finding = await repositories.findings.get(finding_id)
            task = await repositories.tasks.get(finding["task_id"])
            project = await repositories.projects.get(task["project_id"])
            if (
                finding["status"] is not FindingStatus.CONFIRMED
                or not project["exploit_validation_enabled"]
            ):
                raise AutoExploitError("auto_exploit.policy_denied", FailureKind.POLICY)
            permission_mode = project["permission_mode"]
        generated = await self._script_generator.generate(job, finding_id)
        bundle_ref, bundle_version_id = await self._build_and_register_bundle(
            job, finding, generated
        )
        budget = job["resource_budget"]
        return (
            cast(
                ProofRequest,
                {
                    "schema_version": SchemaVersion.VALUE_1_0_0,
                    "id": f"poc:{job['id']}",
                    "job_id": job["id"],
                    "finding_id": finding_id,
                    "script_ref": bundle_ref,
                    "image_digest": image_digest,
                    "permission_mode": permission_mode,
                    "resource_budget": dict(budget),
                    "timeout_seconds": int(budget["timeout_seconds"]),
                },
            ),
            bundle_version_id,
        )


def _producer_identity() -> ToolIdentity:
    return {
        "name": "vulnweaver-proof-bundler",
        "version": "1.0.0",
        "image_digest": None,
    }


def _worker_failure(
    job: Job, code: str, kind: FailureKind, message: str = "proof job rejected"
) -> WorkerResult:
    return WorkerResult(
        schema_version=SchemaVersion.VALUE_1_0_0,
        job_id=job["id"],
        status=JobStatus.FAILED,
        produced_artifact_version_ids=[],
        evidence_ids=[],
        failure=StructuredFailure(
            code=code, kind=kind, message=message, retryable=False, details={}
        ),
    )


class ProofExecutionService:
    """Run one fixed proof/exploit tool through the Sandbox Runner."""

    def __init__(
        self,
        sandbox: ProofSandbox,
        *,
        tool_name: str,
        tool_version: str,
        store: ArtifactStore | None = None,
        output_file_names: tuple[str, ...] = (REPORT_FILE_NAME,),
    ) -> None:
        if not tool_name or not tool_version or not output_file_names:
            raise ValueError("proof tool identity and outputs are required")
        self._sandbox = sandbox
        self._tool_name = tool_name
        self._tool_version = tool_version
        self._store = store
        self._output_file_names = output_file_names

    async def run(
        self,
        request: ProofRequest,
        *,
        finding_status: FindingStatus,
        exploit_validation_enabled: bool,
        cancellation: asyncio.Event,
        kind: PocKind = PocKind.PROOF_OF_CONCEPT,
        expected_target_binding: TargetBinding | None = None,
    ) -> ProofRun:
        try:
            validate_contract("ProofRequest", request)
        except (TypeError, ValueError) as error:
            raise ProofExecutionError("proof request does not satisfy its contract") from error

        decision = evaluate_exploit_eligibility(
            finding_status,
            exploit_validation_enabled=exploit_validation_enabled,
        )
        if kind is PocKind.EXPLOIT and not decision.allowed:
            return ProofRun(
                self._poc(request, kind, PocStatus.FAILED, PocResult.POLICY_DENIED),
                None,
                _denied_result(request),
            )

        budget = request["resource_budget"]
        sandbox_request = cast(
            SandboxRequest,
            {
                "schema_version": SCHEMA_VERSION,
                "id": f"sandbox-request:{request['id']}",
                "tool_name": self._tool_name,
                "tool_version": self._tool_version,
                "image_digest": request["image_digest"],
                "artifact_kind": ArtifactKind.DERIVED,
                # The single input is the target-bound ExecutionBundle.
                "input_ref": request["script_ref"],
                "arguments": {"finding_id": request["finding_id"], "kind": kind.value},
                "output_file_names": list(self._output_file_names),
                "resource_budget": budget,
                "timeout_seconds": request["timeout_seconds"],
            },
        )
        result = await self._sandbox.run(sandbox_request, cancellation)
        observation = self._read_observation(
            request, kind, result, expected_target_binding=expected_target_binding
        )
        status, poc_result = self._poc_outcome(result, observation)
        return ProofRun(
            self._poc(
                request,
                kind,
                status,
                poc_result,
                run_log_ref=result["stdout_ref"] or result["stderr_ref"],
            ),
            observation,
            result,
        )

    def _read_observation(
        self,
        request: ProofRequest,
        kind: PocKind,
        result: SandboxResult,
        *,
        expected_target_binding: TargetBinding | None,
    ) -> VerificationObservation | None:
        """Load and validate the trusted entrypoint report from CAS, if any."""

        if self._store is None:
            return None
        if result["status"] not in {SandboxStatus.SUCCEEDED, SandboxStatus.FAILED}:
            return None
        report_ref = next(
            (
                output["object_ref"]
                for output in result["outputs"]
                if output["path"] == REPORT_FILE_NAME
            ),
            None,
        )
        if report_ref is None:
            return None
        try:
            buffer = io.BytesIO()
            with self._store.open(report_ref) as source:
                buffer.write(source.read(4 * 1024 * 1024 + 1))
            observation = parse_observation(json.loads(buffer.getvalue().decode("utf-8")))
        except (ArtifactStoreError, OSError, UnicodeDecodeError, ValueError, ObservationError):
            return None
        # A report for a different request or finding is never trusted.
        if expected_target_binding is None:
            return None
        if observation["finding_id"] != request["finding_id"]:
            return None
        if str(observation["kind"]) != kind.value:
            return None
        observed_binding = observation["target_binding"]
        if any(
            observed_binding.get(key) != expected_target_binding.get(key)
            for key in ("artifact_id", "version_id", "artifact_kind", "digest")
        ):
            return None
        return observation

    def _poc_outcome(
        self, result: SandboxResult, observation: VerificationObservation | None
    ) -> tuple[PocStatus, PocResult | None]:
        """Tool success only means the tool ran; the observation decides."""

        if observation is not None:
            verdict_result = poc_result_from_observation(observation)
            status = (
                PocStatus.COMPLETED
                if verdict_result
                in {PocResult.EXPLOITABLE, PocResult.NOT_EXPLOITABLE_UNDER_ENVIRONMENT,
                    PocResult.INCONCLUSIVE}
                else PocStatus.FAILED
            )
            return status, verdict_result
        status = _poc_status(result["status"])
        return status, _poc_result(result)

    @staticmethod
    def _poc(
        request: ProofRequest,
        kind: PocKind,
        status: PocStatus,
        result: PocResult | None,
        *,
        run_log_ref: str | None = None,
    ) -> Poc:
        return cast(
            Poc,
            {
                "schema_version": SCHEMA_VERSION,
                "id": request["id"],
                "finding_id": request["finding_id"],
                "kind": kind,
                "status": status,
                "result": result,
                "script_ref": request["script_ref"],
                "run_log_ref": run_log_ref,
                "image_digest": request["image_digest"],
                "permission_mode": request["permission_mode"],
                "resource_budget": request["resource_budget"],
                "created_at": datetime.now(UTC).isoformat(),
            },
        )


def _denied_result(request: ProofRequest) -> SandboxResult:
    return cast(
        SandboxResult,
        {
            "schema_version": SCHEMA_VERSION,
            "request_id": f"sandbox-request:{request['id']}",
            "status": SandboxStatus.POLICY_DENIED,
            "exit_code": None,
            "stdout_ref": None,
            "stderr_ref": None,
            "outputs": [],
            "resource_usage": {
                "duration_millis": 0,
                "cpu_millis": 0,
                "memory_bytes": 0,
                "output_bytes": 0,
            },
            "failure": None,
        },
    )


def _poc_status(status: SandboxStatus) -> PocStatus:
    if status == SandboxStatus.SUCCEEDED:
        return PocStatus.COMPLETED
    if status == SandboxStatus.CANCELLED:
        return PocStatus.CANCELLED
    return PocStatus.FAILED


def _poc_result(result: SandboxResult) -> PocResult:
    status = result["status"]
    if status == SandboxStatus.SUCCEEDED:
        # A finished tool run without a trusted observation proves nothing.
        return PocResult.INCONCLUSIVE
    if status == SandboxStatus.TIMED_OUT:
        return PocResult.TIMEOUT
    if status == SandboxStatus.POLICY_DENIED:
        return PocResult.POLICY_DENIED
    if status == SandboxStatus.CANCELLED:
        return PocResult.ENVIRONMENT_ERROR
    return PocResult.TOOL_ERROR
