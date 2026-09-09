import type {
  Artifact,
  ArtifactKind,
  ArtifactVersion,
  CreateProjectRequest,
  CreateTaskRequest,
  ErrorResponse,
  Finding,
  Job,
  Project,
  QueueEvent,
  Task,
  WorkerResult,
} from "@vulnweaver/contracts";

export interface Session {
  schema_version: "1.0.0";
  username: string;
  must_change_password: boolean;
  csrf_token?: string;
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
  me: () => request<Session>("/api/auth/me"),
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
  createReport: (taskId: string, payload: {
    artifact_id: string;
    version_id: string;
    parent_version_id?: string | null;
    format: "markdown" | "sarif";
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
