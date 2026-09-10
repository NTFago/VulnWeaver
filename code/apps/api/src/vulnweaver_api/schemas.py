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


class RegistrationRequest(StrictModel):
    schema_version: Literal["1.0.0"]
    username: str = Field(min_length=1, max_length=128, pattern=r"^\S(?:.*\S)?$")
    password: str = Field(min_length=12, max_length=1024)


class InstallationStatusResponse(StrictModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    registration_open: bool


DigestPattern = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$", max_length=71)]


class SandboxResourceBudgetModel(StrictModel):
    cpu_millis: int = Field(default=0, ge=0, le=100_000_000)
    memory_bytes: int = Field(default=0, ge=0)
    disk_bytes: int = Field(default=0, ge=0)
    timeout_seconds: int = Field(default=0, ge=0, le=86_400)


class SandboxBudgetsModel(StrictModel):
    afl: SandboxResourceBudgetModel = Field(default_factory=SandboxResourceBudgetModel)
    proof: SandboxResourceBudgetModel = Field(default_factory=SandboxResourceBudgetModel)
    binary: SandboxResourceBudgetModel = Field(default_factory=SandboxResourceBudgetModel)


class FuzzBudgetsModel(StrictModel):
    max_executions: int = Field(default=0, ge=0, le=1_000_000_000)
    max_duration_seconds: int = Field(default=0, ge=0, le=86_400)
    max_crashes: int = Field(default=0, ge=0, le=10_000)


class ToolImageDigestsModel(StrictModel):
    binary_tools: DigestPattern | None = None
    proof_tool: DigestPattern | None = None
    afl_casr: DigestPattern | None = None


class ProductSettingsBody(StrictModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    review_model_base_url: str = Field(default="", max_length=2048)
    review_model_name: str = Field(default="", max_length=256)
    review_model_timeout_seconds: float = Field(default=60, ge=1, le=600)
    review_model_max_attempts: int = Field(default=2, ge=1, le=10)
    review_model_repair_attempts: int = Field(default=1, ge=0, le=5)
    review_model_min_interval_seconds: float = Field(default=0, ge=0, le=3600)
    review_model_api_key: str | None = Field(default=None, min_length=1, max_length=4096)
    clear_review_model_api_key: bool = False
    tool_image_digests: ToolImageDigestsModel = Field(default_factory=ToolImageDigestsModel)
    sandbox_budgets: SandboxBudgetsModel = Field(default_factory=SandboxBudgetsModel)
    fuzz_budgets: FuzzBudgetsModel = Field(default_factory=FuzzBudgetsModel)
    sandbox_runner_timeout_seconds: int = Field(default=0, ge=0, le=86_400)
    fuzz_runner_timeout_seconds: int = Field(default=0, ge=0, le=86_400)
    angr_enabled: bool | None = None


class ProductSettingsResponse(StrictModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    review_model_base_url: str
    review_model_name: str
    review_model_timeout_seconds: float
    review_model_max_attempts: int
    review_model_repair_attempts: int
    review_model_min_interval_seconds: float
    api_key_configured: bool
    tool_image_digests: ToolImageDigestsModel
    sandbox_budgets: SandboxBudgetsModel
    fuzz_budgets: FuzzBudgetsModel
    sandbox_runner_timeout_seconds: int
    fuzz_runner_timeout_seconds: int
    angr_enabled: bool | None


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


class CreateProofJobBody(StrictModel):
    schema_version: Literal["1.0.0"]
    script_ref: str = Field(min_length=1, max_length=2048)
    image_digest: str = Field(min_length=1, max_length=128)
    permission_mode: Literal["request_permission", "full_access"]
    resource_budget: ResourceBudgetModel
    kind: Literal["proof_of_concept", "exploit"] = "proof_of_concept"


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
