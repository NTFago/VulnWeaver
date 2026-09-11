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
    SEMANTIC_AUDIT = 'semantic_audit'
    BINARY_ANALYSIS = 'binary_analysis'
    REVIEW = 'review'
    FUZZ = 'fuzz'
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

class SandboxStatus(StrEnum):
    SUCCEEDED = 'succeeded'
    FAILED = 'failed'
    TIMED_OUT = 'timed_out'
    CANCELLED = 'cancelled'
    ORPHANED = 'orphaned'
    POLICY_DENIED = 'policy_denied'

class FuzzStatus(StrEnum):
    SUCCEEDED = 'succeeded'
    PARTIAL = 'partial'
    FAILED = 'failed'
    TIMED_OUT = 'timed_out'
    CANCELLED = 'cancelled'

class NetworkAccess(StrEnum):
    NONE = 'none'
    ALLOWLIST = 'allowlist'

class CapabilityStatus(StrEnum):
    AVAILABLE = 'available'
    UNAVAILABLE = 'unavailable'

class StaticToolStatus(StrEnum):
    SUCCEEDED = 'succeeded'
    UNAVAILABLE = 'unavailable'
    FAILED = 'failed'

class AnnotationTargetKind(StrEnum):
    FUNCTION = 'function'
    FINDING = 'finding'

class BinaryFormat(StrEnum):
    ELF = 'elf'
    PE = 'pe'

class BinaryArchitecture(StrEnum):
    X86 = 'x86'
    X86_64 = 'x86_64'

class BinaryAnalysisStatus(StrEnum):
    COMPLETE = 'complete'
    PARTIAL = 'partial'

class BinaryXrefType(StrEnum):
    CALL = 'call'
    JUMP = 'jump'
    DATA = 'data'

class BinarySymbolicStatus(StrEnum):
    COMPLETED = 'completed'
    PARTIAL = 'partial'
    FAILED = 'failed'

class PairNodeKind(StrEnum):
    FUNCTION = 'function'
    BASIC_BLOCK = 'basic_block'
    INSTRUCTION = 'instruction'
    PARAMETER = 'parameter'
    VARIABLE = 'variable'
    MEMORY_OBJECT = 'memory_object'
    SOURCE_LOCATION = 'source_location'

class PairEdgeType(StrEnum):
    CALL = 'call'
    CONTROL_FLOW = 'control_flow'
    DEF_USE = 'def_use'
    DATA_FLOW = 'data_flow'
    TAINT = 'taint'
    XREF = 'xref'

class CrashRecord(TypedDict):
    schema_version: SchemaVersion
    id: Identifier
    artifact_version_id: Identifier
    input_ref: ObjectReference
    input_digest: Sha256Digest
    signal: str | None
    exit_code: int | None
    stack_frames: list[str]
    stack_hash: Sha256Digest
    stderr_ref: ObjectReference | None
    fuzz_tool: ToolIdentity
    tool: ToolIdentity
    created_at: str

class HarnessSource(TypedDict):
    source: str

class FuzzRequest(TypedDict):
    schema_version: SchemaVersion
    id: Identifier
    job_id: Identifier
    sandbox_request: SandboxRequest
    artifact_version_id: Identifier
    seed_refs: list[ObjectReference]
    max_executions: int
    max_duration_seconds: int
    max_crashes: int
    collect_coverage: bool

class FuzzResult(TypedDict):
    schema_version: SchemaVersion
    job_id: Identifier
    status: FuzzStatus
    executions: int
    coverage_percent: float | None
    crash_ids: list[Identifier]
    created_at: str
    failure: StructuredFailure | None

class FuzzToolSummary(TypedDict):
    schema_version: SchemaVersion
    executions: int
    coverage_percent: float | None

class CrashManifestEntry(TypedDict):
    input_path: str
    input_digest: Sha256Digest
    signal: str | None
    exit_code: int | None
    stack_frames: list[str]

class CrashManifest(TypedDict):
    schema_version: SchemaVersion
    crashes: list[CrashManifestEntry]

class SandboxOutput(TypedDict):
    path: str
    object_ref: ObjectReference
    digest: Sha256Digest
    size_bytes: int

class SandboxResourceUsage(TypedDict):
    duration_millis: int
    cpu_millis: int
    memory_bytes: int
    output_bytes: int

class SandboxRequest(TypedDict):
    schema_version: SchemaVersion
    id: Identifier
    tool_name: Identifier
    tool_version: str
    image_digest: Sha256Digest
    artifact_kind: ArtifactKind
    input_ref: ObjectReference
    arguments: JsonObject
    output_file_names: list[str]
    resource_budget: ResourceBudget
    timeout_seconds: int

class SandboxResult(TypedDict):
    schema_version: SchemaVersion
    request_id: Identifier
    status: SandboxStatus
    exit_code: int | None
    stdout_ref: ObjectReference | None
    stderr_ref: ObjectReference | None
    outputs: list[SandboxOutput]
    resource_usage: SandboxResourceUsage
    failure: StructuredFailure | None

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

class SourceFileRecord(TypedDict):
    path: str
    size_bytes: int
    digest: Sha256Digest
    language: str | None
    parse_status: Literal['indexed', 'unsupported', 'binary', 'too_large', 'parse_error']

class SourceParameter(TypedDict):
    name: str
    type: str | None

class SourceFunction(TypedDict):
    id: Identifier
    name: str
    qualified_name: str
    kind: Literal['function', 'method', 'constructor']
    language: str
    parameters: list[SourceParameter]
    location: SourceLocation

class SourceCall(TypedDict):
    caller_id: Identifier
    callee: str
    location: SourceLocation

class SourceImportResult(TypedDict):
    schema_version: SchemaVersion
    artifact_version_id: Identifier
    files: list[SourceFileRecord]
    functions: list[SourceFunction]
    calls: list[SourceCall]
    capability_profile: CapabilityProfile

class StaticAnalysisDiagnostic(TypedDict):
    tool_name: Identifier
    rule_id: str
    severity: Severity
    message: str
    location: SourceLocation
    cwe_ids: list[str]
    properties: JsonObject

class StaticToolRun(TypedDict):
    tool_name: Identifier
    tool_version: str | None
    status: StaticToolStatus
    exit_code: int | None
    reason: str | None

class StaticAnalysisResult(TypedDict):
    schema_version: SchemaVersion
    artifact_version_id: Identifier
    diagnostics: list[StaticAnalysisDiagnostic]
    tool_runs: list[StaticToolRun]
    created_at: str

class BinarySection(TypedDict):
    name: str
    virtual_address: int
    virtual_size: int
    file_offset: int
    file_size: int
    readable: bool
    writable: bool
    executable: bool

class BinaryFunction(TypedDict):
    name: str
    address: int
    size: int
    file_offset: int | None
    attributes: JsonObject

class BinaryInstruction(TypedDict):
    address: int
    file_offset: int | None
    bytes: str
    mnemonic: str
    operands: str
    function_name: str | None

class BinaryBasicBlock(TypedDict):
    function_name: str | None
    start_address: int
    end_address: int
    successor_addresses: list[int]

class BinaryXref(TypedDict):
    source_address: int
    target_address: int
    type: BinaryXrefType
    source_function: str | None
    target_symbol: str | None

class BinarySymbolicFact(TypedDict):
    function_address: int
    status: BinarySymbolicStatus
    steps: int
    explored_states: int
    reached_addresses: list[int]
    unconstrained_states: int
    reason: str | None

class BinaryPseudocode(TypedDict):
    function_name: str
    address: int
    text: str
    tool_name: Identifier

class BinaryString(TypedDict):
    value: str
    encoding: Literal['ascii', 'utf-16le']
    file_offset: int
    virtual_address: int | None

class BinaryImport(TypedDict):
    library: str | None
    name: str | None
    ordinal: int | None
    address: int | None

class BinaryToolRun(TypedDict):
    tool_name: Identifier
    tool_version: str | None
    status: StaticToolStatus
    exit_code: int | None
    reason: str | None
    raw_output: str | None

class BinaryAnalysisResult(TypedDict):
    schema_version: SchemaVersion
    artifact_version_id: Identifier
    analyzed_artifact_version_id: Identifier
    format: BinaryFormat
    architecture: BinaryArchitecture
    bits: Literal[32, 64]
    endianness: Literal['little', 'big']
    image_base: int
    entry_point: int
    compiler: str | None
    packer: str | None
    packed: bool
    sections: list[BinarySection]
    functions: list[BinaryFunction]
    instructions: list[BinaryInstruction]
    basic_blocks: list[BinaryBasicBlock]
    xrefs: list[BinaryXref]
    pseudocode: list[BinaryPseudocode]
    symbolic_facts: list[BinarySymbolicFact]
    strings: list[BinaryString]
    imports: list[BinaryImport]
    tool_runs: list[BinaryToolRun]
    status: BinaryAnalysisStatus
    created_at: str

class PairFunction(TypedDict):
    schema_version: SchemaVersion
    id: Identifier
    artifact_version_id: Identifier
    name: str
    symbol: str | None
    language: str
    source_location: SourceLocation | None
    binary_location: BinaryLocation | None
    signature: str | None
    attributes: JsonObject

class PairNode(TypedDict):
    schema_version: SchemaVersion
    id: Identifier
    artifact_version_id: Identifier
    function_id: Identifier | None
    kind: PairNodeKind
    location: SourceLocation | BinaryLocation | None
    attributes: JsonObject

class PairEdge(TypedDict):
    schema_version: SchemaVersion
    id: Identifier
    artifact_version_id: Identifier
    source_node_id: Identifier
    target_node_id: Identifier
    type: PairEdgeType
    scope: str
    confidence: float
    evidence_id: Identifier | None
    attributes: JsonObject

class PairRaw(TypedDict):
    schema_version: SchemaVersion
    id: Identifier
    artifact_version_id: Identifier
    tool: ToolIdentity
    format: str
    object_ref: ObjectReference
    created_at: str

class BinaryLocation(TypedDict):
    artifact_version_id: Identifier
    image_base: NotRequired[int]
    virtual_address: int
    file_offset: int | None
    instruction_end: NotRequired[int]

type FindingLocation = SourceLocation | BinaryLocation

class DataflowStep(TypedDict):
    pair_node_id: Identifier
    label: str
    order: int

class CallPathStep(TypedDict):
    relation: Literal['target', 'caller', 'callee']
    function_name: str
    path: str | None
    line: int | None
    address: int | None

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
    failure: StructuredFailure | None
    idempotency_key: IdempotencyKey
    resource_budget: ResourceBudget
    created_at: str
    updated_at: str

class Job(TypedDict):
    schema_version: SchemaVersion
    id: Identifier
    task_id: Identifier
    kind: JobKind
    tool: NotRequired[ToolIdentity]
    arguments: NotRequired[JsonObject]
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
    duration_ms: NotRequired[int]
    result_refs: NotRequired[list[ObjectReference]]
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
    call_path: list[CallPathStep]
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

class ExploitScript(TypedDict):
    schema_version: SchemaVersion
    script: str
    rationale: str

class CriticalLogicAssessment(TypedDict):
    schema_version: SchemaVersion
    assessments: list[dict[str, JsonValue]]

class ProofRequest(TypedDict):
    schema_version: SchemaVersion
    id: Identifier
    job_id: Identifier
    finding_id: Identifier
    script_ref: ObjectReference
    image_digest: Sha256Digest
    permission_mode: PermissionMode
    resource_budget: ResourceBudget
    timeout_seconds: int

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

class ActionPlanProposal(TypedDict):
    schema_version: SchemaVersion
    steps: list[ActionStep]
    rationale: str

class SemanticAuditFinding(TypedDict):
    cwe_id: Identifier
    title: str
    severity: Severity
    rationale: str
    path: NotRequired[str]
    start_line: NotRequired[int]
    end_line: NotRequired[int]
    address: NotRequired[int]

class SemanticAuditReport(TypedDict):
    schema_version: SchemaVersion
    summary: NotRequired[str]
    findings: list[SemanticAuditFinding]

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
    failure: StructuredFailure | None

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
    resource_budget: NotRequired[ResourceBudget]

class CreateTaskRequest(TypedDict):
    schema_version: SchemaVersion
    artifact_version_ids: list[Identifier]
    resource_budget: NotRequired[ResourceBudget]

class LoginRequest(TypedDict):
    schema_version: SchemaVersion
    username: str
    password: str

class RegistrationRequest(TypedDict):
    schema_version: SchemaVersion
    username: str
    password: str

class ReadablePseudocodeItem(TypedDict):
    function_name: NotRequired[str]
    address: int
    text: str

class ReadablePseudocodeReport(TypedDict):
    schema_version: SchemaVersion
    pseudocode: list[ReadablePseudocodeItem]

class ProductSettings(TypedDict):
    schema_version: SchemaVersion
    review_model_base_url: str
    review_model_name: str
    review_model_timeout_seconds: float
    review_model_max_attempts: int
    review_model_repair_attempts: int
    review_model_min_interval_seconds: float
    review_model_context_window_tokens: NotRequired[int]
    review_model_api_key: NotRequired[str | None]
    clear_review_model_api_key: NotRequired[bool]
    tool_image_digests: NotRequired[ToolImageDigests]
    model_tiers: NotRequired[ModelTierSettings]
    tier_api_keys: NotRequired[TierApiKeys]
    clear_tier_api_keys: NotRequired[list[Literal['planning', 'audit', 'review', 'report']]]
    sandbox_budgets: NotRequired[SandboxBudgets]
    fuzz_budgets: NotRequired[FuzzBudgets]
    agent_loop_budgets: NotRequired[AgentLoopBudgets]
    sandbox_runner_timeout_seconds: NotRequired[int]
    fuzz_runner_timeout_seconds: NotRequired[int]
    angr_enabled: NotRequired[bool | None]

class ToolImageDigests(TypedDict):
    binary_tools: NotRequired[Sha256Digest | None]
    proof_tool: NotRequired[Sha256Digest | None]
    afl_casr: NotRequired[Sha256Digest | None]

class SandboxResourceBudget(TypedDict):
    cpu_millis: NotRequired[int]
    memory_bytes: NotRequired[int]
    disk_bytes: NotRequired[int]
    timeout_seconds: NotRequired[int]

class SandboxBudgets(TypedDict):
    afl: NotRequired[SandboxResourceBudget]
    proof: NotRequired[SandboxResourceBudget]
    binary: NotRequired[SandboxResourceBudget]

class FuzzBudgets(TypedDict):
    max_executions: NotRequired[int]
    max_duration_seconds: NotRequired[int]
    max_crashes: NotRequired[int]

class AgentLoopBudgets(TypedDict):
    audit_deadline_seconds: NotRequired[int]
    reverse_planning_deadline_seconds: NotRequired[int]

class ModelTierSettings(TypedDict):
    planning: NotRequired[TierModelConfig]
    audit: NotRequired[TierModelConfig]
    review: NotRequired[TierModelConfig]
    report: NotRequired[TierModelConfig]

class TierModelConfig(TypedDict):
    protocol: NotRequired[Literal['openai', 'anthropic']]
    base_url: NotRequired[str]
    model_name: NotRequired[str]
    context_window_tokens: NotRequired[int]
    thinking_mode: NotRequired[Literal['off', 'default', 'custom']]
    thinking_budget_tokens: NotRequired[int]
    timeout_seconds: NotRequired[float]
    max_attempts: NotRequired[int]

class TierApiKeys(TypedDict):
    planning: NotRequired[str | None]
    audit: NotRequired[str | None]
    review: NotRequired[str | None]
    report: NotRequired[str | None]

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
