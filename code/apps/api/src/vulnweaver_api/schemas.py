"""Strict HTTP models mirroring the canonical v1 public contract."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field
from vulnweaver_contracts import (
    AnnotationTargetKind,
    Artifact,
    ArtifactVersion,
    Evidence,
    FindingEvidence,
    FindingStatus,
    Severity,
)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ResourceBudgetModel(StrictModel):
    max_model_tokens: int = Field(ge=0)
    cpu_millis: int = Field(ge=1)
    memory_bytes: int = Field(ge=1024 * 1024)
    disk_bytes: int = Field(ge=1024 * 1024)
    max_tool_concurrency: int = Field(ge=1)
    max_dynamic_runs: int = Field(ge=0)
    timeout_seconds: int = Field(ge=1)


class LoginRequest(StrictModel):
    schema_version: Literal["1.0.0"]
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


class PasswordChangeRequest(StrictModel):
    schema_version: Literal["1.0.0"]
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=12, max_length=1024)


class SessionResponse(StrictModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    username: str
    must_change_password: bool
    csrf_token: str = Field(min_length=32, max_length=256)


class MeResponse(StrictModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    username: str
    must_change_password: bool


class ErrorDetail(StrictModel):
    field: str = Field(min_length=1, max_length=512)
    reason: str = Field(min_length=1, max_length=2048)


class ErrorResponse(StrictModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    error_code: str
    message: str = Field(min_length=1, max_length=4096)
    correlation_id: str
    retryable: bool = False
    details: list[ErrorDetail] = Field(default_factory=lambda: list[ErrorDetail]())


class CreateProjectBody(StrictModel):
    schema_version: Literal["1.0.0"]
    name: str = Field(min_length=1, max_length=256)
    input_scope: list[str] = Field(min_length=1)
    permission_mode: Literal["request_permission", "full_access"]
    exploit_validation_enabled: bool
    resource_budget: ResourceBudgetModel


class CreateTaskBody(StrictModel):
    schema_version: Literal["1.0.0"]
    artifact_version_ids: list[str] = Field(min_length=1)
    resource_budget: ResourceBudgetModel


class CreateAnnotationBody(StrictModel):
    schema_version: Literal["1.0.0"]
    target_kind: AnnotationTargetKind
    target_id: str = Field(min_length=1, max_length=128)
    labels: list[Annotated[str, Field(min_length=1, max_length=128)]] = Field(
        default_factory=list, max_length=128
    )
    note: str = Field(default="", max_length=8192)
    severity_override: Severity | None = None
    supersedes_annotation_id: str | None = Field(default=None, max_length=128)


class ReviewFindingBody(StrictModel):
    schema_version: Literal["1.0.0"]
    outcome: FindingStatus
    rationale: str = Field(min_length=1, max_length=8192)
    supersedes_review_id: str | None = Field(default=None, max_length=128)


class CreateReportJobBody(StrictModel):
    schema_version: Literal["1.0.0"]
    artifact_id: str = Field(min_length=1, max_length=128)
    version_id: str = Field(min_length=1, max_length=128)
    parent_version_id: str | None = Field(default=None, min_length=1, max_length=128)
    format: Literal["markdown", "pdf", "sarif"] = "markdown"


class FindingEvidenceDetail(StrictModel):
    relation: FindingEvidence
    evidence: Evidence


class ArtifactDetail(StrictModel):
    artifact: Artifact
    versions: list[ArtifactVersion]


class HealthResponse(StrictModel):
    status: Literal["ok", "ready"]
