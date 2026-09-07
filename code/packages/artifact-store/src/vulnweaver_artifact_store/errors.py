"""Structured failures for artifact storage boundaries."""

from __future__ import annotations

from collections.abc import Mapping


class ArtifactStoreError(RuntimeError):
    code = "artifact_store_error"
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


class InvalidObjectReference(ArtifactStoreError):
    code = "invalid_object_reference"


class ArtifactTooLarge(ArtifactStoreError):
    code = "artifact_too_large"


class ArtifactNotFound(ArtifactStoreError):
    code = "artifact_not_found"


class ArtifactIntegrityError(ArtifactStoreError):
    code = "artifact_integrity_error"


class ArtifactStoreIOError(ArtifactStoreError):
    code = "artifact_store_io_error"
    retryable = True
