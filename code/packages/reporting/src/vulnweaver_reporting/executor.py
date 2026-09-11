"""Worker adapter for durable Markdown, PDF, and SARIF report jobs."""

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
    Finding,
    Job,
    JobKind,
    JobStatus,
    JsonObject,
    Poc,
    Review,
    SchemaVersion,
    StructuredFailure,
    Task,
    ToolIdentity,
    WorkerResult,
)
from vulnweaver_persistence import Database, EntityNotFound, Repositories

from vulnweaver_reporting.artifacts import register_report
from vulnweaver_reporting.chinese import raw_value
from vulnweaver_reporting.context import ReportContext, SampleSummary
from vulnweaver_reporting.excerpts import SourceCodeReader, collect_excerpts, task_version
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
        source_excerpt_reader: SourceCodeReader | None = None,
    ) -> None:
        self._database = database
        self._registration = registration
        self._tool = tool
        self._max_bytes = max_bytes
        self._source_excerpt_reader = source_excerpt_reader

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
        if not all(
            isinstance(value, str) and value
            for value in (task_id, artifact_id, version_id, parent_version_id)
        ):
            return _failure(job, "report.artifact_target_required", FailureKind.VALIDATION)
        if report_format not in {"markdown", "pdf", "sarif"}:
            return _failure(job, "report.format_unsupported", FailureKind.VALIDATION)
        task_id = cast(str, task_id)
        artifact_id = cast(str, artifact_id)
        version_id = cast(str, version_id)
        parent_version_id = cast(str, parent_version_id)
        if task_id != job["task_id"]:
            return _failure(job, "report.task_mismatch", FailureKind.POLICY)
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
                await task_version(repositories, task, parent_version_id)
                try:
                    existing = await repositories.artifacts.get_version(version_id)
                except EntityNotFound:
                    existing = None
                if existing is not None:
                    if (
                        existing["artifact_id"] != artifact_id
                        or existing.get("parent_version_id") != parent_version_id
                        or existing["generation_config"].get("format") != report_format
                    ):
                        return _failure(job, "report.version_mismatch", FailureKind.POLICY)
                    return _success(job, existing["id"])
                context = await self._report_context(repositories, task, findings)
                # Stable across retries of this immutable report request.
                context["generated_at"] = job["created_at"]
            if report_format != "sarif":
                context["excerpts"], context["excerpt_errors"] = await collect_excerpts(
                    self._database,
                    task,
                    findings,
                    self._source_excerpt_reader,
                )
            if cancellation.is_set():
                return _cancelled(job)
            if report_format == "sarif":
                document = build_sarif(findings, pocs, evidence_by_finding)
                validate_sarif(document)
                content = json.dumps(document, ensure_ascii=True, separators=(",", ":")).encode()
            elif report_format == "pdf":
                with tempfile.TemporaryDirectory(prefix="vulnweaver-report-") as directory:
                    output = render_pdf(
                        findings,
                        Path(directory) / "report.pdf",
                        pocs=pocs,
                        evidence=evidence_by_finding,
                        context=context,
                    )
                    content = output.read_bytes()
            else:
                content = build_markdown(findings, pocs, evidence_by_finding, context).encode()
            result = await register_report(
                self._registration,
                artifact,
                version_id=version_id,
                parent_version_id=parent_version_id,
                produced_by=self._tool,
                content=content,
                generation_config=cast(
                    JsonObject,
                    {"format": report_format, "template_version": "2", "task_id": task_id},
                ),
                created_at=job["created_at"],
                max_bytes=self._max_bytes,
            )
        except (ValueError, KeyError) as error:
            return _failure(job, "report.invalid_request", FailureKind.VALIDATION, str(error))
        except EntityNotFound:
            return _failure(job, "report.source_missing", FailureKind.VALIDATION)
        return _success(job, result.version["id"])

    async def _report_context(
        self,
        repositories: Repositories,
        task: Task,
        findings: list[Finding],
    ) -> ReportContext:
        """Gather task-level report facts; every field stays optional."""
        context = ReportContext(
            task_id=task["id"],
            task_created_at=task["created_at"],
            task_updated_at=task["updated_at"],
            task_result=task["result"].value if task["result"] is not None else None,
            produced_by=_produced_by(self._tool),
            task_status=raw_value(task["status"]),
            generated_at=task["updated_at"],
        )
        failure = task["failure"]
        if failure is not None:
            context["failure_code"] = failure["code"]
            context["failure_kind"] = raw_value(failure["kind"])
            context["failure_message"] = failure["message"]
        context["samples"] = await _sample_summaries(repositories, task)
        context["job_failures"] = [
            f"{job['kind'].value} · {job['failure']['code']}：{job['failure']['message']}"
            for job in await repositories.jobs.list_for_task(task["id"])
            if job["kind"] is not JobKind.REPORT and job["failure"] is not None
        ]
        context["evidence_relations"] = {
            finding["id"]: {
                relation["evidence_id"]: raw_value(relation["relation"])
                for relation in await repositories.findings.list_evidence_relations(finding["id"])
            }
            for finding in findings
        }
        reviews: dict[str, list[Review]] = {}
        for finding in findings:
            reviews[finding["id"]] = await repositories.findings.list_reviews(finding["id"])
        context["reviews"] = reviews
        return context


async def _sample_summaries(repositories: Repositories, task: Task) -> list[SampleSummary]:
    """Summarize exactly the versions selected for this task."""
    samples: list[SampleSummary] = []
    for version_id in task["artifact_version_ids"]:
        try:
            version = await repositories.artifacts.get_version(version_id)
        except EntityNotFound:
            raise ValueError("report.input_version_missing") from None
        artifact = await repositories.artifacts.get(version["artifact_id"])
        if artifact["project_id"] != task["project_id"]:
            raise ValueError("report.source_outside_task")
        filename = version["generation_config"].get("filename")
        samples.append(
            SampleSummary(
                name=filename if isinstance(filename, str) else "",
                digest=version["digest"],
                kind=raw_value(artifact["kind"]),
            )
        )
    return samples


def _produced_by(tool: ToolIdentity) -> str:
    """Render the producing tool identity without leaking internal details."""
    produced = f"{tool['name']}@{tool['version']}"
    digest = tool.get("image_digest")
    return f"{produced}（镜像 {digest}）" if digest else produced


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


def _success(job: Job, version_id: str) -> WorkerResult:
    return WorkerResult(
        schema_version=SchemaVersion.VALUE_1_0_0,
        job_id=job["id"],
        status=JobStatus.SUCCEEDED,
        produced_artifact_version_ids=[version_id],
        evidence_ids=[],
        failure=None,
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
