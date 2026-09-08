"""Generated from schemas/v1/contracts.schema.json; do not edit."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal, NotRequired, TypedDict

SCHEMA_VERSION = "1.0.0"
type JsonValue = None | bool | int | float | str | list[JsonValue] | dict[str, JsonValue]

class SchemaVersion(StrEnum):
    VALUE_1_0_0 = '1.0.0'

class PermissionMode(StrEnum):
    REQUEST_PERMISSION = 'request_permission'
    FULL_ACCESS = 'full_access'

class ArtifactKind(StrEnum):
    SOURCE_ARCHIVE = 'source_archive'
    SOURCE_REPOSITORY = 'source_repository'
    ELF = 'elf'
    PE = 'pe'
    DERIVED = 'derived'

class TaskStatus(StrEnum):
    CREATED = 'created'
    VALIDATING = 'validating'
    ANALYZING = 'analyzing'
    REVIEWING = 'reviewing'
    VERIFYING = 'verifying'
    EXPLOITING = 'exploiting'
    REPORTING = 'reporting'
    COMPLETED = 'completed'
    FAILED = 'failed'
    CANCELLED = 'cancelled'

class TaskResult(StrEnum):
    SUCCESS = 'success'
    PARTIAL = 'partial'
    NO_FINDINGS = 'no_findings'

class JobStatus(StrEnum):
    PENDING = 'pending'
    QUEUED = 'queued'
    RUNNING = 'running'
    WAITING_PERMISSION = 'waiting_permission'
    SUCCEEDED = 'succeeded'
    FAILED = 'failed'
    CANCELLED = 'cancelled'

class JobKind(StrEnum):
    VALIDATE = 'validate'
    IMPORT = 'import'
    SOURCE_ANALYSIS = 'source_analysis'
    BINARY_ANALYSIS = 'binary_analysis'
    REVIEW = 'review'
    PROOF = 'proof'
    EXPLOIT = 'exploit'
    REPORT = 'report'

class RunStatus(StrEnum):
    CREATED = 'created'
    RUNNING = 'running'
    SUCCEEDED = 'succeeded'
    FAILED = 'failed'
    CANCELLED = 'cancelled'

class FindingStatus(StrEnum):
    CANDIDATE = 'candidate'
    CONFIRMED = 'confirmed'
    FALSE_POSITIVE = 'false_positive'
    DISPUTED = 'disputed'
    UNVERIFIABLE = 'unverifiable'

class FindingCategory(StrEnum):
    MEMORY_CORRUPTION = 'memory_corruption'
    INJECTION = 'injection'
    AUTH_OR_BUSINESS_LOGIC = 'auth_or_business_logic'
    STATIC_ONLY = 'static_only'

class Severity(StrEnum):
    INFO = 'info'
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'

class EvidenceType(StrEnum):
    MODEL_EXPLANATION = 'model_explanation'
    TOOL_OUTPUT = 'tool_output'
    CODE_SNIPPET = 'code_snippet'
    DATAFLOW_PATH = 'dataflow_path'
    CRASH_RECORD = 'crash_record'
    REPRODUCTION_RESULT = 'reproduction_result'
    EXPLOIT_RECORD = 'exploit_record'
    REVIEW_CONCLUSION = 'review_conclusion'
    HUMAN_CONFIRMATION = 'human_confirmation'

class EvidenceStrength(StrEnum):
    CONTEXTUAL = 'contextual'
    SUPPORTING = 'supporting'
    STRONG = 'strong'

class EvidenceRelation(StrEnum):
    SUPPORTS = 'supports'
    CONTRADICTS = 'contradicts'
    CONTEXTUAL = 'contextual'

class PocKind(StrEnum):
    PROOF_OF_CONCEPT = 'proof_of_concept'
    EXPLOIT = 'exploit'

class PocStatus(StrEnum):
    CREATED = 'created'
    QUEUED = 'queued'
    RUNNING = 'running'
    COMPLETED = 'completed'
    FAILED = 'failed'
    CANCELLED = 'cancelled'

class PocResult(StrEnum):
    EXPLOITABLE = 'exploitable'
    NOT_EXPLOITABLE_UNDER_ENVIRONMENT = 'not_exploitable_under_environment'
    INCONCLUSIVE = 'inconclusive'
    TOOL_ERROR = 'tool_error'
    ENVIRONMENT_ERROR = 'environment_error'
    TIMEOUT = 'timeout'
    POLICY_DENIED = 'policy_denied'

class FailureKind(StrEnum):
    VALIDATION = 'validation'
    POLICY = 'policy'
    TIMEOUT = 'timeout'
    TOOL = 'tool'
    ENVIRONMENT = 'environment'
    DEPENDENCY = 'dependency'
    CANCELLED = 'cancelled'
    INTERNAL = 'internal'

class RiskLevel(StrEnum):
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'

class NetworkAccess(StrEnum):
    NONE = 'none'
    ALLOWLIST = 'allowlist'

class CapabilityStatus(StrEnum):
    AVAILABLE = 'available'
    UNAVAILABLE = 'unavailable'

class AnnotationTargetKind(StrEnum):
    FUNCTION = 'function'
    FINDING = 'finding'

type Identifier = str

type Sha256Digest = str

type ObjectReference = str

type IdempotencyKey = str

type JsonObject = dict[str, JsonValue]

class ResourceBudget(TypedDict):
    max_model_tokens: int
    cpu_millis: int
    memory_bytes: int
    disk_bytes: int
    max_tool_concurrency: int
    max_dynamic_runs: int
    timeout_seconds: int

class RetryPolicy(TypedDict):
    max_attempts: int
    backoff_seconds: float
    retryable_failure_kinds: list[FailureKind]

class Lease(TypedDict):
    owner: Identifier
    fencing_token: NotRequired[Identifier]
    expires_at: str
    heartbeat_interval_seconds: int

class StructuredFailure(TypedDict):
    code: Identifier
    kind: FailureKind
    message: str
    retryable: bool
    details: JsonObject

class ToolIdentity(TypedDict):
    name: Identifier
    version: str
    image_digest: Sha256Digest | None

class DecisionRecord(TypedDict):
    sequence: int
    decision: str
    reason: str
    created_at: str

class TokenUsage(TypedDict):
    input_tokens: int
    output_tokens: int

class SourceLocation(TypedDict):
    artifact_version_id: Identifier
    path: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int

class BinaryLocation(TypedDict):
    artifact_version_id: Identifier
    image_base: NotRequired[int]
    virtual_address: int
    file_offset: int
    instruction_end: NotRequired[int]

type FindingLocation = SourceLocation | BinaryLocation

class DataflowStep(TypedDict):
    pair_node_id: Identifier
    label: str
    order: int

class NetworkPolicy(TypedDict):
    access: NetworkAccess
    allowed_hosts: list[str]

class FilesystemPolicy(TypedDict):
    input_read_only: Literal[True]
    isolated_output: Literal[True]
    allow_host_paths: Literal[False]

class Project(TypedDict):
    schema_version: SchemaVersion
    id: Identifier
    name: str
    input_scope: list[str]
    permission_mode: PermissionMode
    exploit_validation_enabled: bool
    resource_budget: ResourceBudget
    created_at: str

class Artifact(TypedDict):
    schema_version: SchemaVersion
    id: Identifier
    project_id: Identifier
    kind: ArtifactKind
    current_version_id: Identifier
    created_at: str

class ArtifactVersion(TypedDict):
    schema_version: SchemaVersion
    id: Identifier
    artifact_id: Identifier
    digest: Sha256Digest
    object_ref: ObjectReference
    parent_version_id: NotRequired[Identifier | None]
    produced_by: NotRequired[ToolIdentity | None]
    generation_config: JsonObject
    created_at: str

class Task(TypedDict):
    schema_version: SchemaVersion
    id: Identifier
    project_id: Identifier
    artifact_version_ids: list[Identifier]
    status: TaskStatus
    result: TaskResult | None
    idempotency_key: IdempotencyKey
    resource_budget: ResourceBudget
    created_at: str
    updated_at: str

class Job(TypedDict):
    schema_version: SchemaVersion
    id: Identifier
    task_id: Identifier
    kind: JobKind
    input_refs: list[ObjectReference]
    status: JobStatus
    idempotency_key: IdempotencyKey
    resource_budget: ResourceBudget
    retry_policy: RetryPolicy
    attempt: int
    lease: Lease | None
    failure: StructuredFailure | None
    created_at: str
    updated_at: str

class AgentRun(TypedDict):
    schema_version: SchemaVersion
    id: Identifier
    task_id: Identifier
    status: RunStatus
    model: str
    prompt_hash: Sha256Digest
    input_refs: list[ObjectReference]
    decisions: list[DecisionRecord]
    token_usage: TokenUsage
    failure: StructuredFailure | None
    created_at: str
    updated_at: str

class ToolRun(TypedDict):
    schema_version: SchemaVersion
    id: Identifier
    task_id: Identifier
    job_id: Identifier
    status: RunStatus
    tool: ToolIdentity
    input_refs: list[ObjectReference]
    command_hash: Sha256Digest
    exit_code: int | None
    failure: StructuredFailure | None
    created_at: str
    updated_at: str

class Finding(TypedDict):
    schema_version: SchemaVersion
    id: Identifier
    task_id: Identifier
    category: FindingCategory
    cwe_id: str
    title: str
    severity: Severity
    confidence: float
    location: FindingLocation
    dataflow: list[DataflowStep]
    status: FindingStatus
    evidence_ids: list[Identifier]
    review_ids: list[Identifier]
    poc_ids: list[Identifier]
    fix_suggestion: str
    created_at: str

class Evidence(TypedDict):
    schema_version: SchemaVersion
    id: Identifier
    type: EvidenceType
    strength: EvidenceStrength
    artifact_ref: ObjectReference
    digest: Sha256Digest
    tool: ToolIdentity | None
    input_ref: ObjectReference
    command_hash: Sha256Digest | None
    exit_code: int | None
    stdout_ref: ObjectReference | None
    stderr_ref: ObjectReference | None
    replay_recipe: JsonObject
    created_at: str

class FindingEvidence(TypedDict):
    schema_version: SchemaVersion
    finding_id: Identifier
    evidence_id: Identifier
    relation: EvidenceRelation
    weight: float
    created_by: Identifier
    created_at: str

class Poc(TypedDict):
    schema_version: SchemaVersion
    id: Identifier
    finding_id: Identifier
    kind: PocKind
    status: PocStatus
    result: PocResult | None
    script_ref: ObjectReference
    run_log_ref: ObjectReference | None
    image_digest: Sha256Digest
    permission_mode: PermissionMode
    resource_budget: ResourceBudget
    created_at: str

class Review(TypedDict):
    schema_version: SchemaVersion
    id: Identifier
    finding_id: Identifier
    outcome: FindingStatus
    rationale: str
    model: str
    supersedes_review_id: Identifier | None
    created_at: str

class Annotation(TypedDict):
    schema_version: SchemaVersion
    id: Identifier
    task_id: Identifier
    target_kind: AnnotationTargetKind
    target_id: Identifier
    labels: list[str]
    note: str
    severity_override: Severity | None
    author_id: Identifier
    supersedes_annotation_id: Identifier | None
    created_at: str

class FindingPolicyRule(TypedDict):
    category: FindingCategory
    required_facts: list[Identifier]
    require_strong_reproducible_evidence: Literal[True]

class FindingPolicy(TypedDict):
    schema_version: SchemaVersion
    rules: list[FindingPolicyRule]

class ActionStep(TypedDict):
    step_id: Identifier
    tool_name: Identifier
    tool_version: str
    input_refs: list[ObjectReference]
    arguments: JsonObject
    expected_output_types: list[Identifier]
    reason: str

class ActionPlan(TypedDict):
    schema_version: SchemaVersion
    id: Identifier
    task_id: Identifier
    agent_run_id: Identifier
    steps: list[ActionStep]
    created_at: str

class ToolSpec(TypedDict):
    schema_version: SchemaVersion
    name: Identifier
    version: str
    image_digest: Sha256Digest
    risk_level: RiskLevel
    accepted_artifacts: list[ArtifactKind]
    command_schema: JsonObject
    output_schema: JsonObject
    network_policy: NetworkPolicy
    filesystem_policy: FilesystemPolicy
    resource_limits: ResourceBudget
    approval_required: bool
    timeout_seconds: int
    retry_policy: RetryPolicy

class Capability(TypedDict):
    name: Identifier
    status: CapabilityStatus
    tool_name: Identifier | None
    reason: str | None

class CapabilityProfile(TypedDict):
    schema_version: SchemaVersion
    artifact_version_id: Identifier
    languages: list[str]
    architectures: list[str]
    build_systems: list[str]
    capabilities: list[Capability]
    created_at: str

class JobRequestedPayload(TypedDict):
    job_id: Identifier
    task_id: Identifier
    job_kind: JobKind
    attempt: int

class JobStatusChangedPayload(TypedDict):
    job_id: Identifier
    previous_status: JobStatus
    status: JobStatus
    failure: StructuredFailure | None

class TaskStatusChangedPayload(TypedDict):
    task_id: Identifier
    previous_status: TaskStatus
    status: TaskStatus
    result: TaskResult | None

class TaskRequestedPayload(TypedDict):
    task_id: Identifier
    artifact_version_ids: list[Identifier]

class TaskRequestedEvent(TypedDict):
    schema_version: SchemaVersion
    event_id: Identifier
    event_type: Literal['task.requested']
    aggregate_id: Identifier
    sequence: Literal[0]
    occurred_at: str
    correlation_id: Identifier
    causation_id: Identifier | None
    payload: TaskRequestedPayload

class JobRequestedEvent(TypedDict):
    schema_version: SchemaVersion
    event_id: Identifier
    event_type: Literal['job.requested']
    aggregate_id: Identifier
    sequence: int
    occurred_at: str
    correlation_id: Identifier
    causation_id: Identifier | None
    payload: JobRequestedPayload

class JobStatusChangedEvent(TypedDict):
    schema_version: SchemaVersion
    event_id: Identifier
    event_type: Literal['job.status_changed']
    aggregate_id: Identifier
    sequence: int
    occurred_at: str
    correlation_id: Identifier
    causation_id: Identifier | None
    payload: JobStatusChangedPayload

class TaskStatusChangedEvent(TypedDict):
    schema_version: SchemaVersion
    event_id: Identifier
    event_type: Literal['task.status_changed']
    aggregate_id: Identifier
    sequence: int
    occurred_at: str
    correlation_id: Identifier
    causation_id: Identifier | None
    payload: TaskStatusChangedPayload

type QueueEvent = (
    TaskRequestedEvent
    | JobRequestedEvent
    | JobStatusChangedEvent
    | TaskStatusChangedEvent
)

class ErrorDetail(TypedDict):
    field: str
    reason: str

class ErrorResponse(TypedDict):
    schema_version: SchemaVersion
    error_code: Identifier
    message: str
    correlation_id: Identifier
    retryable: bool
    details: list[ErrorDetail]

class CreateProjectRequest(TypedDict):
    schema_version: SchemaVersion
    name: str
    input_scope: list[str]
    permission_mode: PermissionMode
    exploit_validation_enabled: bool
    resource_budget: ResourceBudget

class CreateTaskRequest(TypedDict):
    schema_version: SchemaVersion
    artifact_version_ids: list[Identifier]
    resource_budget: ResourceBudget

class LoginRequest(TypedDict):
    schema_version: SchemaVersion
    username: str
    password: str

class PasswordChangeRequest(TypedDict):
    schema_version: SchemaVersion
    current_password: str
    new_password: str

class SessionResponse(TypedDict):
    schema_version: SchemaVersion
    username: str
    must_change_password: bool
    csrf_token: str

class MeResponse(TypedDict):
    schema_version: SchemaVersion
    username: str
    must_change_password: bool

class ArtifactDetail(TypedDict):
    artifact: Artifact
    versions: list[ArtifactVersion]

class HealthResponse(TypedDict):
    status: Literal['ok', 'ready']

class WorkerRequest(TypedDict):
    schema_version: SchemaVersion
    event: JobRequestedEvent
    job: Job
    capability_profile: CapabilityProfile

class WorkerResult(TypedDict):
    schema_version: SchemaVersion
    job_id: Identifier
    status: JobStatus
    produced_artifact_version_ids: list[Identifier]
    evidence_ids: list[Identifier]
    failure: StructuredFailure | None
