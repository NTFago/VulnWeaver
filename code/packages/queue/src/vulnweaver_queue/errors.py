"""Structured Redis transport failures."""

from __future__ import annotations

from collections.abc import Mapping


class QueueError(RuntimeError):
    code = "queue_error"
    retryable = False

    def __init__(self, message: str, *, details: Mapping[str, object] | None = None) -> None:
        self.message = message
        self.details = dict(details or {})
        super().__init__(message)

    def as_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
            "details": self.details,
        }


class QueueConfigurationError(QueueError):
    code = "queue_configuration_error"


class QueueUnavailable(QueueError):
    code = "queue_unavailable"
    retryable = True


class QueueMessageConflict(QueueError):
    code = "queue_message_conflict"


class MalformedQueueMessage(QueueError):
    code = "malformed_queue_message"
