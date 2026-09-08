"""Construction of versioned task intake and state events."""

from datetime import UTC, datetime
from uuid import uuid4

from vulnweaver_contracts import (
    SchemaVersion,
    Task,
    TaskRequestedEvent,
    TaskStatus,
    TaskStatusChangedEvent,
)


def task_requested(task: Task, occurred_at: str) -> TaskRequestedEvent:
    return TaskRequestedEvent(
        schema_version=SchemaVersion.VALUE_1_0_0,
        event_id=_identifier("event"),
        event_type="task.requested",
        aggregate_id=task["id"],
        sequence=0,
        occurred_at=occurred_at,
        correlation_id=task["id"],
        causation_id=None,
        payload={
            "task_id": task["id"],
            "artifact_version_ids": task["artifact_version_ids"],
        },
    )


def task_cancelled(
    task: Task, previous_status: TaskStatus, sequence: int
) -> TaskStatusChangedEvent:
    return TaskStatusChangedEvent(
        schema_version=SchemaVersion.VALUE_1_0_0,
        event_id=_identifier("event"),
        event_type="task.status_changed",
        aggregate_id=task["id"],
        sequence=sequence,
        occurred_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        correlation_id=task["id"],
        causation_id=None,
        payload={
            "task_id": task["id"],
            "previous_status": previous_status,
            "status": TaskStatus.CANCELLED,
            "result": None,
        },
    )


def _identifier(prefix: str) -> str:
    return f"{prefix}:{uuid4().hex}"
