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
from vulnweaver_persistence.personal_auth import PersonalAccount, PersonalSession
from vulnweaver_persistence.repositories import (
    AgentRunRepository,
    CreateResult,
    EvidenceRepository,
    FindingRepository,
    JobAttemptFailure,
    JobCompletionResult,
    JobEnqueueResult,
    JobLeaseClaim,
    JobLeaseClaimOutcome,
    OutboxMessage,
    Repositories,
    StoredCheckpoint,
    TaskCancellationResult,
    TaskStatusUpdateResult,
)

__all__ = [
    "AgentRunRepository",
    "CreateResult",
    "EvidenceRepository",
    "FindingRepository",
    "Database",
    "DatabaseSettings",
    "EntityConflict",
    "EntityNotFound",
    "IdempotencyConflict",
    "JobAttemptFailure",
    "JobEnqueueResult",
    "JobCompletionResult",
    "JobLeaseClaim",
    "JobLeaseClaimOutcome",
    "JobLeaseConflict",
    "OutboxMessage",
    "StoredCheckpoint",
    "TaskStatusUpdateResult",
    "PersonalAccount",
    "PersonalSession",
    "PersistenceError",
    "PersistenceInvariantError",
    "Repositories",
    "TaskCancellationResult",
    "downgrade_database",
    "metadata",
    "upgrade_database",
]
