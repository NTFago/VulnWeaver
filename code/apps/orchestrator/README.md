# VulnWeaver Orchestrator Service

The service consumes versioned `task.requested` events, resumes from PostgreSQL-backed
checkpoints, validates the task's registered artifacts, selects the source or binary
pipeline, evaluates the first ActionPlan through the Policy Engine, and atomically
records the initial Job plus Outbox event. Approval-required jobs are persisted in
`waiting_permission` without dispatch.

Runtime configuration requires `DATABASE_URL`, `REDIS_URL`, and `TOOL_SPEC_DIRECTORY`.
The ToolSpec directory is deployment-owned trusted configuration; the service does not
invent image digests or accept tool definitions from model output. T12/T16 provide the
concrete source and binary tool specifications and worker images.
