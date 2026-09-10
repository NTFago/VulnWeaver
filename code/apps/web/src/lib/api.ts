import type {
  Artifact,
  ArtifactKind,
  ArtifactVersion,
  CreateProjectRequest,
  CreateTaskRequest,
  ErrorResponse,
  Finding,
  PairFunction,
  Evidence,
  FindingEvidence,
  Poc,
  Job,
  Project,
  QueueEvent,
  ResourceBudget,
  Review,
  Task,
  WorkerResult,
} from "@vulnweaver/contracts";

export interface Session {
  schema_version: "1.0.0";
  username: string;
  must_change_password: boolean;
  csrf_token?: string;
}

export interface InstallationStatus {
  schema_version: "1.0.0";
  registration_open: boolean;
}

export interface SandboxResourceBudget {
  cpu_millis: number;
  memory_bytes: number;
  disk_bytes: number;
  timeout_seconds: number;
}

export interface ToolImageDigests {
  binary_tools: string | null;
  proof_tool: string | null;
  afl_casr: string | null;
}

export interface FuzzBudgets {
  max_executions: number;
  max_duration_seconds: number;
  max_crashes: number;
}

export interface ProductSettings {
  schema_version: "1.0.0";
  review_model_base_url: string;
  review_model_name: string;
  review_model_timeout_seconds: number;
  review_model_max_attempts: number;
  review_model_repair_attempts: number;
  review_model_min_interval_seconds: number;
  api_key_configured: boolean;
  tool_image_digests: ToolImageDigests;
  sandbox_budgets: {
    afl: SandboxResourceBudget;
    proof: SandboxResourceBudget;
    binary: SandboxResourceBudget;
  };
  fuzz_budgets: FuzzBudgets;
  sandbox_runner_timeout_seconds: number;
  fuzz_runner_timeout_seconds: number;
  angr_enabled: boolean | null;
  model_tiers: Record<"planning" | "audit" | "review" | "report", TierModelConfig>;
  tier_api_keys_configured: Record<string, boolean>;
}

export interface TierModelConfig {
  protocol: "openai" | "anthropic";
  base_url: string;
  model_name: string;
  context_window_tokens: number;
  thinking_mode: "off" | "default" | "custom";
  thinking_budget_tokens: number;
  timeout_seconds: number;
  max_attempts: number;
}


export interface FindingEvidenceDetail {
  relation: FindingEvidence;
  evidence: Evidence;
}

export interface ArtifactDetail {
  artifact: Artifact;
  versions: ArtifactVersion[];
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code: string,
    readonly correlationId?: string,
  ) {
    super(message);
  }
}

const schemaVersion = "1.0.0" as const;

function cookie(name: string): string | undefined {
  return document.cookie
    .split(";")
    .map((item) => item.trim())
    .find((item) => item.startsWith(`${name}=`))
    ?.slice(name.length + 1);
}

function idempotencyKey(): string {
  return crypto.randomUUID();
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(path, { credentials: "same-origin", ...init });
  if (!response.ok) {
    let body: ErrorResponse | undefined;
    try {
      body = (await response.json()) as ErrorResponse;
    } catch {
      // An upstream proxy can fail before the API returns its structured envelope.
    }
    throw new ApiError(
      body?.message ?? `请求失败 (${response.status})`,
      response.status,
      body?.error_code ?? "transport_error",
      body?.correlation_id ?? response.headers.get("X-Correlation-ID") ?? undefined,
    );
  }
  return response.status === 204 ? (undefined as T) : ((await response.json()) as T);
}

function writeHeaders(idempotent = false): HeadersInit {
  return {
    "Content-Type": "application/json",
    "X-CSRF-Token": decodeURIComponent(cookie("vulnweaver_csrf") ?? ""),
    ...(idempotent ? { "Idempotency-Key": idempotencyKey() } : {}),
  };
}

export const api = {
  installation: () => request<InstallationStatus>("/api/auth/installation"),
  me: () => request<Session>("/api/auth/me"),
  register: (username: string, password: string) =>
    request<Session>("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ schema_version: schemaVersion, username, password }),
    }),
  login: (username: string, password: string) =>
    request<Session>("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ schema_version: schemaVersion, username, password }),
    }),
  logout: () => request<void>("/api/auth/logout", { method: "POST", headers: writeHeaders() }),
  changePassword: (current_password: string, new_password: string) =>
    request<void>("/api/auth/password", {
      method: "POST",
      headers: writeHeaders(true),
      body: JSON.stringify({ schema_version: schemaVersion, current_password, new_password }),
    }),
  settings: () => request<ProductSettings>("/api/settings"),
  updateSettings: (
    settings: Omit<ProductSettings, "schema_version" | "api_key_configured" | "tier_api_keys_configured"> & {
      review_model_api_key: string | null; clear_review_model_api_key: boolean;
      tier_api_keys?: Record<string, string>; clear_tier_api_keys?: string[];
    },
  ) =>
    request<ProductSettings>("/api/settings", {
      method: "PUT",
      headers: writeHeaders(),
      body: JSON.stringify({ schema_version: schemaVersion, ...settings }),
    }),
  projects: () => request<Project[]>("/api/projects"),
  createProject: (payload: Omit<CreateProjectRequest, "schema_version">) =>
    request<Project>("/api/projects", {
      method: "POST",
      headers: writeHeaders(true),
      body: JSON.stringify({ schema_version: schemaVersion, ...payload }),
    }),
  artifacts: (projectId: string) => request<Artifact[]>(`/api/projects/${projectId}/artifacts`),
  artifact: (projectId: string, artifactId: string) =>
    request<ArtifactDetail>(`/api/projects/${projectId}/artifacts/${artifactId}`),
  artifactContentUrl: (artifactId: string, versionId?: string) =>
    `/api/artifacts/${encodeURIComponent(artifactId)}/content${versionId ? `?version_id=${encodeURIComponent(versionId)}` : ""}`,
  artifactVersion: (versionId: string) =>
    request<ArtifactVersion>(`/api/artifact-versions/${encodeURIComponent(versionId)}`),
  upload: (projectId: string, kind: ArtifactKind, file: File) =>
    request<ArtifactDetail>(`/api/projects/${projectId}/artifacts?kind=${kind}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/octet-stream",
        "X-CSRF-Token": decodeURIComponent(cookie("vulnweaver_csrf") ?? ""),
        "X-Artifact-Filename": encodeURIComponent(file.name),
        "Idempotency-Key": idempotencyKey(),
      },
      body: file,
    }),
  tasks: (projectId: string) => request<Task[]>(`/api/projects/${projectId}/tasks`),
  createTask: (projectId: string, payload: Omit<CreateTaskRequest, "schema_version">) =>
    request<Task>(`/api/projects/${projectId}/tasks`, {
      method: "POST",
      headers: writeHeaders(true),
      body: JSON.stringify({ schema_version: schemaVersion, ...payload }),
    }),
  task: (taskId: string) => request<Task>(`/api/tasks/${taskId}`),
  jobs: (taskId: string) => request<Job[]>(`/api/tasks/${taskId}/jobs`),
  jobResult: (jobId: string) => request<WorkerResult | { job_id: string; status: string; result: null }>(`/api/jobs/${jobId}/result`),
  events: (taskId: string, after = -1) =>
    request<QueueEvent[]>(`/api/tasks/${taskId}/events?after=${after}`),
  findings: (taskId: string) => request<Finding[]>(`/api/tasks/${taskId}/findings`),
  pair: (taskId: string) => request<PairFunction[]>(`/api/tasks/${encodeURIComponent(taskId)}/pair`),
  agentRuns: (taskId: string) => request<Record<string, unknown>[]>(`/api/tasks/${encodeURIComponent(taskId)}/agent-runs`),
  pairNeighborhood: (taskId: string, functionId: string, depth = 1) =>
    request<Record<string, unknown>>(`/api/tasks/${encodeURIComponent(taskId)}/pair/function/${encodeURIComponent(functionId)}/neighborhood?depth=${depth}`),
  annotations: (taskId: string) => request<Record<string, unknown>[]>(`/api/tasks/${encodeURIComponent(taskId)}/annotations`),
  createAnnotation: (taskId: string, payload: { target_kind: string; target_id: string; labels: string[]; note: string; severity_override?: string | null }) =>
    request<Record<string, unknown>>(`/api/tasks/${encodeURIComponent(taskId)}/annotations`, {
      method: "POST", headers: writeHeaders(true), body: JSON.stringify({ schema_version: schemaVersion, ...payload }),
    }),
  reviewFinding: (findingId: string, outcome: string, rationale: string) =>
    request<Review>(`/api/findings/${encodeURIComponent(findingId)}/review`, {
      method: "PATCH", headers: writeHeaders(true), body: JSON.stringify({ schema_version: schemaVersion, outcome, rationale }),
    }),
  findingReviews: (findingId: string) =>
    request<Review[]>(`/api/findings/${encodeURIComponent(findingId)}/reviews`),
  findingEvidence: (findingId: string) => request<FindingEvidenceDetail[]>(`/api/findings/${findingId}/evidence`),
  findingPocs: (findingId: string) => request<Poc[]>(`/api/findings/${findingId}/pocs`),
  observability: (taskId: string) => request<Record<string, unknown>>(`/api/tasks/${taskId}/observability`),
  createProof: (findingId: string, payload: {
    script_ref: string; image_digest: string; permission_mode: "request_permission" | "full_access";
    resource_budget: ResourceBudget; kind: "proof_of_concept" | "exploit";
  }) => request<Job>(`/api/findings/${encodeURIComponent(findingId)}/proof`, {
    method: "POST", headers: writeHeaders(true),
    body: JSON.stringify({ schema_version: schemaVersion, ...payload }),
  }),
  createReport: (taskId: string, payload: {
    artifact_id: string;
    version_id: string;
    parent_version_id?: string | null;
    format: "markdown" | "pdf" | "sarif";
  }) => request<Job>(`/api/tasks/${taskId}/reports`, {
    method: "POST",
    headers: writeHeaders(true),
    body: JSON.stringify({ schema_version: schemaVersion, ...payload }),
  }),
  cancelTask: (taskId: string) =>
    request<Task>(`/api/tasks/${taskId}/cancel`, {
      method: "POST",
      headers: writeHeaders(true),
    }),
};

export function taskEventSocket(taskId: string, after: number): WebSocket {
  const protocol = location.protocol === "https:" ? "wss:" : "ws:";
  return new WebSocket(
    `${protocol}//${location.host}/api/tasks/${encodeURIComponent(taskId)}/events/ws?after=${after}`,
  );
}
