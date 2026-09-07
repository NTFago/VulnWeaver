"""PostgreSQL migrations and transaction-scoped repositories."""

from vulnweaver_persistence.database import Database, DatabaseSettings
from vulnweaver_persistence.errors import (
    EntityConflict,
    EntityNotFound,
    IdempotencyConflict,
    JobLeaseConflict,
    PersistenceError,
    PersistenceInvariantError,
)
from vulnweaver_persistence.migrations import downgrade_database, upgrade_database
from vulnweaver_persistence.models import metadata
from vulnweaver_persistence.repositories import (
    CreateResult,
    JobCompletionResult,
    JobEnqueueResult,
    JobLeaseClaim,
    JobLeaseClaimOutcome,
    OutboxMessage,
    Repositories,
)

__all__ = [
    "CreateResult",
    "Database",
    "DatabaseSettings",
    "EntityConflict",
    "EntityNotFound",
    "IdempotencyConflict",
    "JobEnqueueResult",
    "JobCompletionResult",
    "JobLeaseClaim",
    "JobLeaseClaimOutcome",
    "JobLeaseConflict",
    "OutboxMessage",
    "PersistenceError",
    "PersistenceInvariantError",
    "Repositories",
    "downgrade_database",
    "metadata",
    "upgrade_database",
]
