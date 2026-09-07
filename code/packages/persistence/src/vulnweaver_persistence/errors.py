"""Structured persistence failures safe to expose through service boundaries."""

from __future__ import annotations

from collections.abc import Mapping


class PersistenceError(RuntimeError):
    code = "persistence_error"
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


class IdempotencyConflict(PersistenceError):
    code = "idempotency_conflict"


class EntityConflict(PersistenceError):
    code = "entity_conflict"


class EntityNotFound(PersistenceError):
    code = "entity_not_found"


class PersistenceInvariantError(PersistenceError):
    code = "persistence_invariant_violation"


class JobLeaseConflict(PersistenceError):
    code = "job_lease_conflict"
    retryable = True
