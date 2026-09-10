// Generated from schemas/v1/contracts.schema.json; do not edit.

export const SCHEMA_VERSION = "1.0.0" as const;
export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

export type SchemaVersion = "1.0.0";

export type PermissionMode = "request_permission" | "full_access";

export type ArtifactKind = "source_archive" | "source_repository" | "elf" | "pe" | "derived";

export type TaskStatus = "created" | "validating" | "analyzing" | "reviewing" | "verifying" | "exploiting" | "reporting" | "completed" | "failed" | "cancelled";

export type TaskResult = "success" | "partial" | "no_findings";

export type JobStatus = "pending" | "queued" | "running" | "waiting_permission" | "succeeded" | "failed" | "cancelled";

export type JobKind = "validate" | "import" | "source_analysis" | "semantic_audit" | "binary_analysis" | "review" | "fuzz" | "proof" | "exploit" | "report";

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

export type SandboxStatus = "succeeded" | "failed" | "timed_out" | "cancelled" | "orphaned" | "policy_denied";

export type FuzzStatus = "succeeded" | "partial" | "failed" | "timed_out" | "cancelled";

export interface CrashRecord {
  schema_version: SchemaVersion;
  id: Identifier;
  artifact_version_id: Identifier;
  input_ref: ObjectReference;
  input_digest: Sha256Digest;
  signal: string | null;
  exit_code: number | null;
  stack_frames: Array<string>;
  stack_hash: Sha256Digest;
  stderr_ref: ObjectReference | null;
  fuzz_tool: ToolIdentity;
  tool: ToolIdentity;
  created_at: string;
}

export interface HarnessSource {
  source: string;
}

export interface FuzzRequest {
  schema_version: SchemaVersion;
  id: Identifier;
  job_id: Identifier;
  sandbox_request: SandboxRequest;
  artifact_version_id: Identifier;
  seed_refs: Array<ObjectReference>;
  max_executions: number;
  max_duration_seconds: number;
  max_crashes: number;
  collect_coverage: boolean;
}

export interface FuzzResult {
  schema_version: SchemaVersion;
  job_id: Identifier;
  status: FuzzStatus;
  executions: number;
  coverage_percent: number | null;
  crash_ids: Array<Identifier>;
  created_at: string;
  failure: StructuredFailure | null;
}

export interface FuzzToolSummary {
  schema_version: SchemaVersion;
  executions: number;
  coverage_percent: number | null;
}

export interface CrashManifestEntry {
  input_path: string;
  input_digest: Sha256Digest;
  signal: string | null;
  exit_code: number | null;
  stack_frames: Array<string>;
}

export interface CrashManifest {
  schema_version: SchemaVersion;
  crashes: Array<CrashManifestEntry>;
}

export interface SandboxOutput {
  path: string;
  object_ref: ObjectReference;
  digest: Sha256Digest;
  size_bytes: number;
}

export interface SandboxResourceUsage {
  duration_millis: number;
  cpu_millis: number;
  memory_bytes: number;
  output_bytes: number;
}

export interface SandboxRequest {
  schema_version: SchemaVersion;
  id: Identifier;
  tool_name: Identifier;
  tool_version: string;
  image_digest: Sha256Digest;
  artifact_kind: ArtifactKind;
  input_ref: ObjectReference;
  arguments: JsonObject;
  output_file_names: Array<string>;
  resource_budget: ResourceBudget;
  timeout_seconds: number;
}

export interface SandboxResult {
  schema_version: SchemaVersion;
  request_id: Identifier;
  status: SandboxStatus;
  exit_code: number | null;
  stdout_ref: ObjectReference | null;
  stderr_ref: ObjectReference | null;
  outputs: Array<SandboxOutput>;
  resource_usage: SandboxResourceUsage;
  failure: StructuredFailure | null;
}

export type NetworkAccess = "none" | "allowlist";

export type CapabilityStatus = "available" | "unavailable";

export type StaticToolStatus = "succeeded" | "unavailable" | "failed";

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

export interface SourceFileRecord {
  path: string;
  size_bytes: number;
  digest: Sha256Digest;
  language: string | null;
  parse_status: "indexed" | "unsupported" | "binary" | "too_large" | "parse_error";
}

export interface SourceParameter {
  name: string;
  type: string | null;
}

export interface SourceFunction {
  id: Identifier;
  name: string;
  qualified_name: string;
  kind: "function" | "method" | "constructor";
  language: string;
  parameters: Array<SourceParameter>;
  location: SourceLocation;
}

export interface SourceCall {
  caller_id: Identifier;
  callee: string;
  location: SourceLocation;
}

export interface SourceImportResult {
  schema_version: SchemaVersion;
  artifact_version_id: Identifier;
  files: Array<SourceFileRecord>;
  functions: Array<SourceFunction>;
  calls: Array<SourceCall>;
  capability_profile: CapabilityProfile;
}

export interface StaticAnalysisDiagnostic {
  tool_name: Identifier;
  rule_id: string;
  severity: Severity;
  message: string;
  location: SourceLocation;
  cwe_ids: Array<string>;
  properties: JsonObject;
}

export interface StaticToolRun {
  tool_name: Identifier;
  tool_version: string | null;
  status: StaticToolStatus;
  exit_code: number | null;
  reason: string | null;
}

export interface StaticAnalysisResult {
  schema_version: SchemaVersion;
  artifact_version_id: Identifier;
  diagnostics: Array<StaticAnalysisDiagnostic>;
  tool_runs: Array<StaticToolRun>;
  created_at: string;
}

export type BinaryFormat = "elf" | "pe";

export type BinaryArchitecture = "x86" | "x86_64";

export type BinaryAnalysisStatus = "complete" | "partial";

export interface BinarySection {
  name: string;
  virtual_address: number;
  virtual_size: number;
  file_offset: number;
  file_size: number;
  readable: boolean;
  writable: boolean;
  executable: boolean;
}

export interface BinaryFunction {
  name: string;
  address: number;
  size: number;
  file_offset: number | null;
  attributes: JsonObject;
}

export interface BinaryInstruction {
  address: number;
  file_offset: number | null;
  bytes: string;
  mnemonic: string;
  operands: string;
  function_name: string | null;
}

export interface BinaryBasicBlock {
  function_name: string | null;
  start_address: number;
  end_address: number;
  successor_addresses: Array<number>;
}

export type BinaryXrefType = "call" | "jump" | "data";

export interface BinaryXref {
  source_address: number;
  target_address: number;
  type: BinaryXrefType;
  source_function: string | null;
  target_symbol: string | null;
}

export type BinarySymbolicStatus = "completed" | "partial" | "failed";

export interface BinarySymbolicFact {
  function_address: number;
  status: BinarySymbolicStatus;
  steps: number;
  explored_states: number;
  reached_addresses: Array<number>;
  unconstrained_states: number;
  reason: string | null;
}

export interface BinaryPseudocode {
  function_name: string;
  address: number;
  text: string;
  tool_name: Identifier;
}

export interface BinaryString {
  value: string;
  encoding: "ascii" | "utf-16le";
  file_offset: number;
  virtual_address: number | null;
}

export interface BinaryImport {
  library: string | null;
  name: string | null;
  ordinal: number | null;
  address: number | null;
}

export interface BinaryToolRun {
  tool_name: Identifier;
  tool_version: string | null;
  status: StaticToolStatus;
  exit_code: number | null;
  reason: string | null;
  raw_output: string | null;
}

export interface BinaryAnalysisResult {
  schema_version: SchemaVersion;
  artifact_version_id: Identifier;
  analyzed_artifact_version_id: Identifier;
  format: BinaryFormat;
  architecture: BinaryArchitecture;
  bits: 32 | 64;
  endianness: "little" | "big";
  image_base: number;
  entry_point: number;
  compiler: string | null;
  packer: string | null;
  packed: boolean;
  sections: Array<BinarySection>;
  functions: Array<BinaryFunction>;
  instructions: Array<BinaryInstruction>;
  basic_blocks: Array<BinaryBasicBlock>;
  xrefs: Array<BinaryXref>;
  pseudocode: Array<BinaryPseudocode>;
  symbolic_facts: Array<BinarySymbolicFact>;
  strings: Array<BinaryString>;
  imports: Array<BinaryImport>;
  tool_runs: Array<BinaryToolRun>;
  status: BinaryAnalysisStatus;
  created_at: string;
}

export type PairNodeKind = "function" | "basic_block" | "instruction" | "parameter" | "variable" | "memory_object" | "source_location";

export type PairEdgeType = "call" | "control_flow" | "def_use" | "data_flow" | "taint" | "xref";

export interface PairFunction {
  schema_version: SchemaVersion;
  id: Identifier;
  artifact_version_id: Identifier;
  name: string;
  symbol: string | null;
  language: string;
  source_location: SourceLocation | null;
  binary_location: BinaryLocation | null;
  signature: string | null;
  attributes: JsonObject;
}

export interface PairNode {
  schema_version: SchemaVersion;
  id: Identifier;
  artifact_version_id: Identifier;
  function_id: Identifier | null;
  kind: PairNodeKind;
  location: SourceLocation | BinaryLocation | null;
  attributes: JsonObject;
}

export interface PairEdge {
  schema_version: SchemaVersion;
  id: Identifier;
  artifact_version_id: Identifier;
  source_node_id: Identifier;
  target_node_id: Identifier;
  type: PairEdgeType;
  scope: string;
  confidence: number;
  evidence_id: Identifier | null;
  attributes: JsonObject;
}

export interface PairRaw {
  schema_version: SchemaVersion;
  id: Identifier;
  artifact_version_id: Identifier;
  tool: ToolIdentity;
  format: string;
  object_ref: ObjectReference;
  created_at: string;
}

export interface BinaryLocation {
  artifact_version_id: Identifier;
  image_base?: number;
  virtual_address: number;
  file_offset: number | null;
  instruction_end?: number;
}

export type FindingLocation = SourceLocation | BinaryLocation;

export interface DataflowStep {
  pair_node_id: Identifier;
  label: string;
  order: number;
}

export interface CallPathStep {
  relation: "target" | "caller" | "callee";
  function_name: string;
  path: string | null;
  line: number | null;
  address: number | null;
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
  tool?: ToolIdentity;
  arguments?: JsonObject;
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
  duration_ms?: number;
  result_refs?: Array<ObjectReference>;
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
  call_path: Array<CallPathStep>;
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

export interface ExploitScript {
  schema_version: SchemaVersion;
  script: string;
  rationale: string;
}

export interface CriticalLogicAssessment {
  schema_version: SchemaVersion;
  assessments: Array<Record<string, JsonValue>>;
}

export interface ProofRequest {
  schema_version: SchemaVersion;
  id: Identifier;
  job_id: Identifier;
  finding_id: Identifier;
  script_ref: ObjectReference;
  image_digest: Sha256Digest;
  permission_mode: PermissionMode;
  resource_budget: ResourceBudget;
  timeout_seconds: number;
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

export interface ActionPlanProposal {
  schema_version: SchemaVersion;
  steps: Array<ActionStep>;
  rationale: string;
}

export interface SemanticAuditFinding {
  cwe_id: Identifier;
  title: string;
  severity: Severity;
  rationale: string;
  path?: string;
  start_line?: number;
  end_line?: number;
  address?: number;
}

export interface SemanticAuditReport {
  schema_version: SchemaVersion;
  summary?: string;
  findings: Array<SemanticAuditFinding>;
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

export interface TaskRequestedPayload {
  task_id: Identifier;
  artifact_version_ids: Array<Identifier>;
}

export interface TaskRequestedEvent {
  schema_version: SchemaVersion;
  event_id: Identifier;
  event_type: "task.requested";
  aggregate_id: Identifier;
  sequence: 0;
  occurred_at: string;
  correlation_id: Identifier;
  causation_id: Identifier | null;
  payload: TaskRequestedPayload;
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

export type QueueEvent = TaskRequestedEvent | JobRequestedEvent | JobStatusChangedEvent | TaskStatusChangedEvent;

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

export interface LoginRequest {
  schema_version: SchemaVersion;
  username: string;
  password: string;
}

export interface RegistrationRequest {
  schema_version: SchemaVersion;
  username: string;
  password: string;
}

export interface ReadablePseudocodeItem {
  function_name?: string;
  address: number;
  text: string;
}

export interface ReadablePseudocodeReport {
  schema_version: SchemaVersion;
  pseudocode: Array<ReadablePseudocodeItem>;
}

export interface ProductSettings {
  schema_version: SchemaVersion;
  review_model_base_url: string;
  review_model_name: string;
  review_model_timeout_seconds: number;
  review_model_max_attempts: number;
  review_model_repair_attempts: number;
  review_model_min_interval_seconds: number;
  review_model_api_key?: string | null;
  clear_review_model_api_key?: boolean;
  tool_image_digests?: ToolImageDigests;
  sandbox_budgets?: SandboxBudgets;
  fuzz_budgets?: FuzzBudgets;
  sandbox_runner_timeout_seconds?: number;
  fuzz_runner_timeout_seconds?: number;
  angr_enabled?: boolean | null;
}

export interface ToolImageDigests {
  binary_tools?: Sha256Digest | null;
  proof_tool?: Sha256Digest | null;
  afl_casr?: Sha256Digest | null;
}

export interface SandboxResourceBudget {
  cpu_millis?: number;
  memory_bytes?: number;
  disk_bytes?: number;
  timeout_seconds?: number;
}

export interface SandboxBudgets {
  afl?: SandboxResourceBudget;
  proof?: SandboxResourceBudget;
  binary?: SandboxResourceBudget;
}

export interface FuzzBudgets {
  max_executions?: number;
  max_duration_seconds?: number;
  max_crashes?: number;
}

export interface PasswordChangeRequest {
  schema_version: SchemaVersion;
  current_password: string;
  new_password: string;
}

export interface SessionResponse {
  schema_version: SchemaVersion;
  username: string;
  must_change_password: boolean;
  csrf_token: string;
}

export interface MeResponse {
  schema_version: SchemaVersion;
  username: string;
  must_change_password: boolean;
}

export interface ArtifactDetail {
  artifact: Artifact;
  versions: Array<ArtifactVersion>;
}

export interface HealthResponse {
  status: "ok" | "ready";
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
