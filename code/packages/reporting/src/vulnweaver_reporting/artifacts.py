"""Persist generated reports through the immutable artifact registration service."""

from __future__ import annotations

import io

from vulnweaver_artifact_store import ArtifactRegistrationResult, ArtifactRegistrationService
from vulnweaver_contracts import Artifact, JsonObject, ToolIdentity


async def register_report(
    service: ArtifactRegistrationService,
    artifact: Artifact,
    *,
    version_id: str,
    parent_version_id: str,
    produced_by: ToolIdentity,
    content: bytes,
    generation_config: JsonObject,
    created_at: str,
    max_bytes: int,
) -> ArtifactRegistrationResult:
    """Register one bounded report as an immutable derived artifact version."""
    from vulnweaver_artifact_store import ArtifactVersionRequest

    if not content or len(content) > max_bytes:
        raise ValueError("report content is empty or exceeds the configured limit")
    request = ArtifactVersionRequest(
        id=version_id,
        artifact_id=artifact["id"],
        parent_version_id=parent_version_id,
        produced_by=produced_by,
        generation_config=generation_config,
        created_at=created_at,
    )
    return await service.register_version(
        request,
        io.BytesIO(content),
        max_bytes=max_bytes,
    )
