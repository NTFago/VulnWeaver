# VulnWeaver Orchestrator

This package owns the LangGraph control-plane flow that consumes `task.requested`.
It validates persisted input ownership, selects source or binary import, evaluates the
initial ActionPlan through the Policy Engine, and creates the first Job and Outbox event
in one PostgreSQL transaction.

Every completed graph node writes a detached checkpoint. `PostgresCheckpointStore`
serializes per-task checkpoint sequences with a PostgreSQL advisory transaction lock.
A replay resumes at the node after the latest checkpoint; a crash after Job commit but
before checkpoint commit is safe because Job and Outbox creation are idempotent.

The orchestrator consumer alternates fresh events and stale pending recovery. Permanent
validation or policy failures are recorded on the Task and acknowledged. Unknown
transient failures remain pending for later takeover. Approval-required jobs are stored
as `waiting_permission` without an Outbox event, so a Worker cannot run them before a
separate permission decision requeues them.
