"""Strict HTTP models mirroring the canonical v1 public contract."""

from __future__ import annotations

from typing import Annotated, Any, Literal

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


class AgentLoopBudgetsModel(StrictModel):
    """Wall-clock bounds for the two agent loops, in seconds.

    Zero means "keep the deployment default": the resolver reads a non-positive
    value as unset, exactly as it does for every other budget here.
    """

    audit_deadline_seconds: int = Field(default=0, ge=0, le=86_400)
    reverse_planning_deadline_seconds: int = Field(default=0, ge=0, le=86_400)


class ToolImageDigestsModel(StrictModel):
    binary_tools: DigestPattern | None = None
    proof_tool: DigestPattern | None = None
    afl_casr: DigestPattern | None = None


ModelProtocol = Literal["openai", "anthropic"]
TierName = Literal["planning", "audit", "review", "report"]
ThinkingMode = Literal["off", "default", "custom"]


class TierModelConfigModel(StrictModel):
    protocol: ModelProtocol = "openai"
    base_url: str = Field(default="", max_length=2048)
    model_name: str = Field(default="", max_length=256)
    context_window_tokens: int = Field(default=0, ge=0, le=100_000_000)
    thinking_mode: ThinkingMode = "off"
    thinking_budget_tokens: int = Field(default=0, ge=0, le=1_000_000)
    timeout_seconds: float = Field(default=0, ge=0, le=600)
    max_attempts: int = Field(default=0, ge=0, le=8)


class TierApiKeysModel(StrictModel):
    planning: str | None = Field(default=None, min_length=1, max_length=4096)
    audit: str | None = Field(default=None, min_length=1, max_length=4096)
    review: str | None = Field(default=None, min_length=1, max_length=4096)
    report: str | None = Field(default=None, min_length=1, max_length=4096)


class ModelTiersModel(StrictModel):
    planning: TierModelConfigModel = Field(default_factory=TierModelConfigModel)
    audit: TierModelConfigModel = Field(default_factory=TierModelConfigModel)
    review: TierModelConfigModel = Field(default_factory=TierModelConfigModel)
    report: TierModelConfigModel = Field(default_factory=TierModelConfigModel)


class ProductSettingsBody(StrictModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    review_model_base_url: str = Field(default="", max_length=2048)
    review_model_name: str = Field(default="", max_length=256)
    # These bounds mirror the model gateway's own validation. Accepting a wider range stores a
    # value the worker rejects when it builds its gateway, which leaves every job unprocessed.
    review_model_timeout_seconds: float = Field(default=60, ge=1, le=600)
    review_model_max_attempts: int = Field(default=2, ge=1, le=8)
    review_model_repair_attempts: int = Field(default=1, ge=0, le=3)
    review_model_min_interval_seconds: float = Field(default=0, ge=0, le=60)
    # 0 disables the gateway's context-window trimming for the fallback endpoint.
    review_model_context_window_tokens: int = Field(default=0, ge=0, le=100_000_000)
    review_model_api_key: str | None = Field(default=None, min_length=1, max_length=4096)
    clear_review_model_api_key: bool = False
    tool_image_digests: ToolImageDigestsModel = Field(default_factory=ToolImageDigestsModel)
    sandbox_budgets: SandboxBudgetsModel = Field(default_factory=SandboxBudgetsModel)
    fuzz_budgets: FuzzBudgetsModel = Field(default_factory=FuzzBudgetsModel)
    agent_loop_budgets: AgentLoopBudgetsModel = Field(default_factory=AgentLoopBudgetsModel)
    sandbox_runner_timeout_seconds: int = Field(default=0, ge=0, le=86_400)
    fuzz_runner_timeout_seconds: int = Field(default=0, ge=0, le=86_400)
    angr_enabled: bool | None = None
    model_tiers: ModelTiersModel = Field(default_factory=ModelTiersModel)
    tier_api_keys: TierApiKeysModel = Field(default_factory=TierApiKeysModel)
    clear_tier_api_keys: list[str] = Field(default_factory=list)


class ProductSettingsResponse(StrictModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    review_model_base_url: str
    review_model_name: str
    review_model_timeout_seconds: float
    review_model_max_attempts: int
    review_model_repair_attempts: int
    review_model_min_interval_seconds: float
    review_model_context_window_tokens: int
    api_key_configured: bool
    tool_image_digests: ToolImageDigestsModel
    sandbox_budgets: SandboxBudgetsModel
    fuzz_budgets: FuzzBudgetsModel
    agent_loop_budgets: AgentLoopBudgetsModel
    sandbox_runner_timeout_seconds: int
    fuzz_runner_timeout_seconds: int
    angr_enabled: bool | None
    model_tiers: ModelTiersModel
    tier_api_keys_configured: dict[str, bool]


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
    resource_budget: ResourceBudgetModel | None = None


class CreateTaskBody(StrictModel):
    schema_version: Literal["1.0.0"]
    artifact_version_ids: list[str] = Field(min_length=1)
    # Budgets are inert bookkeeping (ADR-025); an omitted budget inherits the project row.
    resource_budget: ResourceBudgetModel | None = None


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
    # Budgets are inert bookkeeping (ADR-025); an omitted budget inherits the project row.
    resource_budget: ResourceBudgetModel | None = None
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


class AuditTrailDecision(StrictModel):
    sequence: int
    decision: str
    reason: str
    created_at: str


class AuditTrailToolStep(StrictModel):
    step_id: str
    tool: str | None
    succeeded: bool
    failure_code: str | None
    observation: dict[str, Any] | None
    observation_status: Literal["not_recorded"]


class AuditTrailAgentRun(StrictModel):
    id: str
    status: str
    model: str
    prompt_hash: str
    input_refs: list[str]
    result_refs: list[str]
    token_usage: dict[str, int]
    duration_ms: int | None
    failure: dict[str, Any] | None
    created_at: str
    updated_at: str
    role: Literal[
        "semantic_audit",
        "semantic_audit_agent",
        "reverse_analysis_planner",
        "readable_pseudocode",
        "fuzz_harness_generator",
        "critical_logic_analyst",
        "exploit_generator",
        "independent_reviewer",
        "unknown",
    ]
    job_id: str | None
    job_attempt: int | None
    association: Literal[
        "exact_run_id_rule_with_attempt",
        "exact_run_id_rule",
        "unknown",
    ]
    decisions: list[AuditTrailDecision]
    tool_steps: list[AuditTrailToolStep]


class BinaryAnalysisJobSummary(StrictModel):
    job_id: str
    status: str
    attempt: int
    input_refs: list[str]
    output_version_ids: list[str]
    facts_status: Literal["not_exposed"]


class AuditTrailResponse(StrictModel):
    schema_version: Literal["1.0.0"]
    task_id: str
    agent_runs: list[AuditTrailAgentRun]
    binary_analysis_jobs: list[BinaryAnalysisJobSummary]
