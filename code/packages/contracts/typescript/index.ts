// Generated from schemas/v1/contracts.schema.json; do not edit.

export const SCHEMA_VERSION = "1.0.0" as const;
export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

export type SchemaVersion = "1.0.0";

export type PermissionMode = "request_permission" | "full_access";

export type ArtifactKind = "source_archive" | "source_repository" | "elf" | "pe" | "derived";

export type TaskStatus = "created" | "validating" | "analyzing" | "reviewing" | "verifying" | "exploiting" | "reporting" | "completed" | "failed" | "cancelled";

export type TaskResult = "success" | "partial" | "no_findings";

export type JobStatus = "pending" | "queued" | "running" | "waiting_permission" | "succeeded" | "failed" | "cancelled";

export type JobKind = "validate" | "import" | "source_analysis" | "binary_analysis" | "review" | "proof" | "exploit" | "report";

export type RunStatus = "created" | "running" | "succeeded" | "failed" | "cancelled";

export type FindingStatus = "candidate" | "confirmed" | "false_positive" | "disputed" | "unverifiable";

export type FindingCategory = "memory_corruption" | "injection" | "auth_or_business_logic" | "static_only";

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type EvidenceType = "model_explanation" | "tool_output" | "code_snippet" | "dataflow_path" | "crash_record" | "reproduction_result" | "exploit_record" | "review_conclusion" | "human_confirmation";

export type EvidenceStrength = "contextual" | "supporting" | "strong";

export type EvidenceRelation = "supports" | "contradicts" | "contextual";

export type PocKind = "proof_of_concept" | "exploit";

export type PocStatus = "created" | "queued" | "running" | "completed" | "failed" | "cancelled";

export type PocResult = "exploitable" | "not_exploitable_under_environment" | "inconclusive" | "tool_error" | "environment_error" | "timeout" | "policy_denied";

export type FailureKind = "validation" | "policy" | "timeout" | "tool" | "environment" | "dependency" | "cancelled" | "internal";

export type RiskLevel = "low" | "medium" | "high" | "critical";

export type NetworkAccess = "none" | "allowlist";

export type CapabilityStatus = "available" | "unavailable";

export type AnnotationTargetKind = "function" | "finding";

export type Identifier = string;

export type Sha256Digest = string;

export type ObjectReference = string;

export type IdempotencyKey = string;

export type JsonObject = Record<string, JsonValue>;

export interface ResourceBudget {
  max_model_tokens: number;
  cpu_millis: number;
  memory_bytes: number;
  disk_bytes: number;
  max_tool_concurrency: number;
  max_dynamic_runs: number;
  timeout_seconds: number;
}

export interface RetryPolicy {
  max_attempts: number;
  backoff_seconds: number;
  retryable_failure_kinds: Array<FailureKind>;
}

export interface Lease {
  owner: Identifier;
  fencing_token?: Identifier;
  expires_at: string;
  heartbeat_interval_seconds: number;
}

export interface StructuredFailure {
  code: Identifier;
  kind: FailureKind;
  message: string;
  retryable: boolean;
  details: JsonObject;
}

export interface ToolIdentity {
  name: Identifier;
  version: string;
  image_digest: Sha256Digest | null;
}

export interface DecisionRecord {
  sequence: number;
  decision: string;
  reason: string;
  created_at: string;
}

export interface TokenUsage {
  input_tokens: number;
  output_tokens: number;
}

export interface SourceLocation {
  artifact_version_id: Identifier;
  path: string;
  start_line: number;
  start_column: number;
  end_line: number;
  end_column: number;
}

export interface BinaryLocation {
  artifact_version_id: Identifier;
  image_base?: number;
  virtual_address: number;
  file_offset: number;
  instruction_end?: number;
}

export type FindingLocation = SourceLocation | BinaryLocation;

export interface DataflowStep {
  pair_node_id: Identifier;
  label: string;
  order: number;
}

export interface NetworkPolicy {
  access: NetworkAccess;
  allowed_hosts: Array<string>;
}

export interface FilesystemPolicy {
  input_read_only: true;
  isolated_output: true;
  allow_host_paths: false;
}

export interface Project {
  schema_version: SchemaVersion;
  id: Identifier;
  name: string;
  input_scope: Array<string>;
  permission_mode: PermissionMode;
  exploit_validation_enabled: boolean;
  resource_budget: ResourceBudget;
  created_at: string;
}

export interface Artifact {
  schema_version: SchemaVersion;
  id: Identifier;
  project_id: Identifier;
  kind: ArtifactKind;
  current_version_id: Identifier;
  created_at: string;
}

export interface ArtifactVersion {
  schema_version: SchemaVersion;
  id: Identifier;
  artifact_id: Identifier;
  digest: Sha256Digest;
  object_ref: ObjectReference;
  parent_version_id?: Identifier | null;
  produced_by?: ToolIdentity | null;
  generation_config: JsonObject;
  created_at: string;
}

export interface Task {
  schema_version: SchemaVersion;
  id: Identifier;
  project_id: Identifier;
  artifact_version_ids: Array<Identifier>;
  status: TaskStatus;
  result: TaskResult | null;
  idempotency_key: IdempotencyKey;
  resource_budget: ResourceBudget;
  created_at: string;
  updated_at: string;
}

export interface Job {
  schema_version: SchemaVersion;
  id: Identifier;
  task_id: Identifier;
  kind: JobKind;
  input_refs: Array<ObjectReference>;
  status: JobStatus;
  idempotency_key: IdempotencyKey;
  resource_budget: ResourceBudget;
  retry_policy: RetryPolicy;
  attempt: number;
  lease: Lease | null;
  failure: StructuredFailure | null;
  created_at: string;
  updated_at: string;
}

export interface AgentRun {
  schema_version: SchemaVersion;
  id: Identifier;
  task_id: Identifier;
  status: RunStatus;
  model: string;
  prompt_hash: Sha256Digest;
  input_refs: Array<ObjectReference>;
  decisions: Array<DecisionRecord>;
  token_usage: TokenUsage;
  failure: StructuredFailure | null;
  created_at: string;
  updated_at: string;
}

export interface ToolRun {
  schema_version: SchemaVersion;
  id: Identifier;
  task_id: Identifier;
  job_id: Identifier;
  status: RunStatus;
  tool: ToolIdentity;
  input_refs: Array<ObjectReference>;
  command_hash: Sha256Digest;
  exit_code: number | null;
  failure: StructuredFailure | null;
  created_at: string;
  updated_at: string;
}

export interface Finding {
  schema_version: SchemaVersion;
  id: Identifier;
  task_id: Identifier;
  category: FindingCategory;
  cwe_id: string;
  title: string;
  severity: Severity;
  confidence: number;
  location: FindingLocation;
  dataflow: Array<DataflowStep>;
  status: FindingStatus;
  evidence_ids: Array<Identifier>;
  review_ids: Array<Identifier>;
  poc_ids: Array<Identifier>;
  fix_suggestion: string;
  created_at: string;
}

export interface Evidence {
  schema_version: SchemaVersion;
  id: Identifier;
  type: EvidenceType;
  strength: EvidenceStrength;
  artifact_ref: ObjectReference;
  digest: Sha256Digest;
  tool: ToolIdentity | null;
  input_ref: ObjectReference;
  command_hash: Sha256Digest | null;
  exit_code: number | null;
  stdout_ref: ObjectReference | null;
  stderr_ref: ObjectReference | null;
  replay_recipe: JsonObject;
  created_at: string;
}

export interface FindingEvidence {
  schema_version: SchemaVersion;
  finding_id: Identifier;
  evidence_id: Identifier;
  relation: EvidenceRelation;
  weight: number;
  created_by: Identifier;
  created_at: string;
}

export interface Poc {
  schema_version: SchemaVersion;
  id: Identifier;
  finding_id: Identifier;
  kind: PocKind;
  status: PocStatus;
  result: PocResult | null;
  script_ref: ObjectReference;
  run_log_ref: ObjectReference | null;
  image_digest: Sha256Digest;
  permission_mode: PermissionMode;
  resource_budget: ResourceBudget;
  created_at: string;
}

export interface Review {
  schema_version: SchemaVersion;
  id: Identifier;
  finding_id: Identifier;
  outcome: FindingStatus;
  rationale: string;
  model: string;
  supersedes_review_id: Identifier | null;
  created_at: string;
}

export interface Annotation {
  schema_version: SchemaVersion;
  id: Identifier;
  task_id: Identifier;
  target_kind: AnnotationTargetKind;
  target_id: Identifier;
  labels: Array<string>;
  note: string;
  severity_override: Severity | null;
  author_id: Identifier;
  supersedes_annotation_id: Identifier | null;
  created_at: string;
}

export interface FindingPolicyRule {
  category: FindingCategory;
  required_facts: Array<Identifier>;
  require_strong_reproducible_evidence: true;
}

export interface FindingPolicy {
  schema_version: SchemaVersion;
  rules: Array<FindingPolicyRule>;
}

export interface ActionStep {
  step_id: Identifier;
  tool_name: Identifier;
  tool_version: string;
  input_refs: Array<ObjectReference>;
  arguments: JsonObject;
  expected_output_types: Array<Identifier>;
  reason: string;
}

export interface ActionPlan {
  schema_version: SchemaVersion;
  id: Identifier;
  task_id: Identifier;
  agent_run_id: Identifier;
  steps: Array<ActionStep>;
  created_at: string;
}

export interface ToolSpec {
  schema_version: SchemaVersion;
  name: Identifier;
  version: string;
  image_digest: Sha256Digest;
  risk_level: RiskLevel;
  accepted_artifacts: Array<ArtifactKind>;
  command_schema: JsonObject;
  output_schema: JsonObject;
  network_policy: NetworkPolicy;
  filesystem_policy: FilesystemPolicy;
  resource_limits: ResourceBudget;
  approval_required: boolean;
  timeout_seconds: number;
  retry_policy: RetryPolicy;
}

export interface Capability {
  name: Identifier;
  status: CapabilityStatus;
  tool_name: Identifier | null;
  reason: string | null;
}

export interface CapabilityProfile {
  schema_version: SchemaVersion;
  artifact_version_id: Identifier;
  languages: Array<string>;
  architectures: Array<string>;
  build_systems: Array<string>;
  capabilities: Array<Capability>;
  created_at: string;
}

export interface JobRequestedPayload {
  job_id: Identifier;
  task_id: Identifier;
  job_kind: JobKind;
  attempt: number;
}

export interface JobStatusChangedPayload {
  job_id: Identifier;
  previous_status: JobStatus;
  status: JobStatus;
  failure: StructuredFailure | null;
}

export interface TaskStatusChangedPayload {
  task_id: Identifier;
  previous_status: TaskStatus;
  status: TaskStatus;
  result: TaskResult | null;
}

export interface JobRequestedEvent {
  schema_version: SchemaVersion;
  event_id: Identifier;
  event_type: "job.requested";
  aggregate_id: Identifier;
  sequence: number;
  occurred_at: string;
  correlation_id: Identifier;
  causation_id: Identifier | null;
  payload: JobRequestedPayload;
}

export interface JobStatusChangedEvent {
  schema_version: SchemaVersion;
  event_id: Identifier;
  event_type: "job.status_changed";
  aggregate_id: Identifier;
  sequence: number;
  occurred_at: string;
  correlation_id: Identifier;
  causation_id: Identifier | null;
  payload: JobStatusChangedPayload;
}

export interface TaskStatusChangedEvent {
  schema_version: SchemaVersion;
  event_id: Identifier;
  event_type: "task.status_changed";
  aggregate_id: Identifier;
  sequence: number;
  occurred_at: string;
  correlation_id: Identifier;
  causation_id: Identifier | null;
  payload: TaskStatusChangedPayload;
}

export type QueueEvent = JobRequestedEvent | JobStatusChangedEvent | TaskStatusChangedEvent;

export interface ErrorDetail {
  field: string;
  reason: string;
}

export interface ErrorResponse {
  schema_version: SchemaVersion;
  error_code: Identifier;
  message: string;
  correlation_id: Identifier;
  retryable: boolean;
  details: Array<ErrorDetail>;
}

export interface CreateProjectRequest {
  schema_version: SchemaVersion;
  name: string;
  input_scope: Array<string>;
  permission_mode: PermissionMode;
  exploit_validation_enabled: boolean;
  resource_budget: ResourceBudget;
}

export interface CreateTaskRequest {
  schema_version: SchemaVersion;
  artifact_version_ids: Array<Identifier>;
  resource_budget: ResourceBudget;
}

export interface WorkerRequest {
  schema_version: SchemaVersion;
  event: JobRequestedEvent;
  job: Job;
  capability_profile: CapabilityProfile;
}

export interface WorkerResult {
  schema_version: SchemaVersion;
  job_id: Identifier;
  status: JobStatus;
  produced_artifact_version_ids: Array<Identifier>;
  evidence_ids: Array<Identifier>;
  failure: StructuredFailure | null;
}
