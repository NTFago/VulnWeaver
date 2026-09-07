"""Immutable, content-addressed artifact storage."""

from vulnweaver_artifact_store.errors import (
    ArtifactIntegrityError,
    ArtifactNotFound,
    ArtifactStoreError,
    ArtifactStoreIOError,
    ArtifactTooLarge,
    InvalidObjectReference,
)
from vulnweaver_artifact_store.registration import (
    ArtifactRegistrationResult,
    ArtifactRegistrationService,
    ArtifactVersionRequest,
)
from vulnweaver_artifact_store.store import (
    ArtifactStore,
    LocalContentAddressedStore,
    StoredObject,
)

__all__ = [
    "ArtifactIntegrityError",
    "ArtifactNotFound",
    "ArtifactRegistrationResult",
    "ArtifactRegistrationService",
    "ArtifactStore",
    "ArtifactStoreError",
    "ArtifactStoreIOError",
    "ArtifactTooLarge",
    "ArtifactVersionRequest",
    "InvalidObjectReference",
    "LocalContentAddressedStore",
    "StoredObject",
]
