"""Worker adapter for durable Markdown and SARIF report jobs."""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from typing import cast

from vulnweaver_artifact_store import ArtifactRegistrationService
from vulnweaver_contracts import (
    Evidence,
    FailureKind,
    Job,
    JobKind,
    JobStatus,
    JsonObject,
    Poc,
    SchemaVersion,
    StructuredFailure,
    ToolIdentity,
    WorkerResult,
)
from vulnweaver_persistence import Database

from vulnweaver_reporting.artifacts import register_report
from vulnweaver_reporting.markdown import build_markdown
from vulnweaver_reporting.pdf import render_pdf
from vulnweaver_reporting.sarif import build_sarif, validate_sarif


class ReportJobExecutor:
    """Generate and register one report without exposing filesystem paths."""

    def __init__(
        self,
        database: Database,
        registration: ArtifactRegistrationService,
        *,
        tool: ToolIdentity,
        max_bytes: int = 16 * 1024 * 1024,
    ) -> None:
        self._database = database
        self._registration = registration
        self._tool = tool
        self._max_bytes = max_bytes

    async def execute(self, job: Job, cancellation: asyncio.Event) -> WorkerResult:
        if job["kind"] is not JobKind.REPORT:
            return _failure(job, "report.invalid_job_kind", FailureKind.VALIDATION)
        if cancellation.is_set():
            return _cancelled(job)
        arguments = job.get("arguments")
        if not isinstance(arguments, dict):
            return _failure(job, "report.arguments_required", FailureKind.VALIDATION)
        task_id = arguments.get("task_id")
        artifact_id = arguments.get("artifact_id")
        version_id = arguments.get("version_id")
        parent_version_id = arguments.get("parent_version_id")
        report_format = arguments.get("format", "markdown")
        if not all(isinstance(value, str) and value for value in (
            task_id, artifact_id, version_id, parent_version_id
        )):
            return _failure(job, "report.artifact_target_required", FailureKind.VALIDATION)
        if report_format not in {"markdown", "pdf", "sarif"}:
            return _failure(job, "report.format_unsupported", FailureKind.VALIDATION)
        task_id = cast(str, task_id)
        artifact_id = cast(str, artifact_id)
        version_id = cast(str, version_id)
        parent_version_id = cast(str, parent_version_id)
        try:
            async with self._database.transaction() as repositories:
                task = await repositories.tasks.get(task_id)
                findings = await repositories.findings.list_for_task(task["id"])
                pocs: list[Poc] = []
                evidence_by_finding: dict[str, list[Evidence]] = {}
                for finding in findings:
                    pocs.extend(await repositories.pocs.list_for_finding(finding["id"]))
                    evidence_by_finding[finding["id"]] = [
                        await repositories.evidence.get(relation["evidence_id"])
                        for relation in await repositories.findings.list_evidence_relations(
                            finding["id"]
                        )
                    ]
                artifact = await repositories.artifacts.get(artifact_id)
                if (
                    artifact["kind"].value != "derived"
                    or artifact["project_id"] != task["project_id"]
                ):
                    return _failure(job, "report.artifact_mismatch", FailureKind.POLICY)
            if report_format == "sarif":
                document = build_sarif(findings, pocs, evidence_by_finding)
                validate_sarif(document)
                content = json.dumps(document, ensure_ascii=True, separators=(",", ":")).encode()
            elif report_format == "pdf":
                with tempfile.TemporaryDirectory(prefix="vulnweaver-report-") as directory:
                    output = render_pdf(
                        findings, Path(directory) / "report.pdf", pocs=pocs
                    )
                    content = output.read_bytes()
            else:
                content = build_markdown(findings, pocs, evidence_by_finding).encode()
            result = await register_report(
                self._registration,
                artifact,
                version_id=version_id,
                parent_version_id=parent_version_id,
                produced_by=self._tool,
                content=content,
                generation_config=cast(JsonObject, {"format": report_format}),
                created_at=task["updated_at"],
                max_bytes=self._max_bytes,
            )
        except (ValueError, KeyError) as error:
            return _failure(job, "report.invalid_request", FailureKind.VALIDATION, str(error))
        return WorkerResult(
            schema_version=SchemaVersion.VALUE_1_0_0,
            job_id=job["id"],
            status=JobStatus.SUCCEEDED,
            produced_artifact_version_ids=[result.version["id"]],
            evidence_ids=[],
            failure=None,
        )


def _failure(
    job: Job, code: str, kind: FailureKind, message: str = "report job rejected"
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


def _cancelled(job: Job) -> WorkerResult:
    return WorkerResult(
        schema_version=SchemaVersion.VALUE_1_0_0,
        job_id=job["id"],
        status=JobStatus.CANCELLED,
        produced_artifact_version_ids=[],
        evidence_ids=[],
        failure=None,
    )
