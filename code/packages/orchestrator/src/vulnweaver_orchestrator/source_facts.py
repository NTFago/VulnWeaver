"""Resolve source facts only within the task's immutable input boundary."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import cast

from vulnweaver_artifact_store import ArtifactStore, ArtifactStoreError
from vulnweaver_contracts import (
    ArtifactKind,
    ContractValidationError,
    JsonObject,
    SourceLocation,
    validate_contract,
)
from vulnweaver_persistence import Database, EntityNotFound
from vulnweaver_source_analysis import (
    ExcerptLimits,
    SourceExcerpt,
    SourceExcerptReader,
    SourceImportError,
)


@dataclass(frozen=True, slots=True)
class SourceReviewFacts:
    available: bool
    reason_code: str | None
    excerpt: SourceExcerpt | None


class SourceReviewFactLoader:
    def __init__(
        self, database: Database, store: ArtifactStore, *, reader: SourceExcerptReader | None = None
    ) -> None:
        self._database = database
        # The review is one shot per finding: unlike the audit's line-anchored
        # read there is no follow-up window shift, so a span wider than the
        # window would be reviewed blind. The reader's validated ceiling (500
        # lines / 128 KiB) covers real-world parser functions end to end; the
        # audit path keeps its own narrower, paged budget.
        self._reader = reader or SourceExcerptReader(
            store,
            limits=ExcerptLimits(max_lines=500, text_bytes=128 * 1024),
        )

    async def load(self, task_id: str, location: JsonObject) -> SourceReviewFacts:
        try:
            validate_contract("SourceLocation", location)
        except ContractValidationError:
            return SourceReviewFacts(False, "source_location_unsupported", None)
        source_location = cast(SourceLocation, location)
        try:
            async with self._database.transaction() as repositories:
                task = await repositories.tasks.get(task_id)
                version_id = source_location["artifact_version_id"]
                if version_id not in task["artifact_version_ids"]:
                    return SourceReviewFacts(False, "source_outside_task_inputs", None)
                version = await repositories.artifacts.get_version(version_id)
                artifact = await repositories.artifacts.get(version["artifact_id"])
                if artifact["project_id"] != task["project_id"]:
                    return SourceReviewFacts(False, "source_project_mismatch", None)
                if artifact["kind"] not in {
                    ArtifactKind.SOURCE_ARCHIVE,
                    ArtifactKind.SOURCE_REPOSITORY,
                }:
                    return SourceReviewFacts(False, "source_artifact_unsupported", None)
            excerpt = await asyncio.to_thread(self._reader.read, version, source_location)
        except EntityNotFound:
            return SourceReviewFacts(False, "source_metadata_missing", None)
        except SourceImportError as error:
            return SourceReviewFacts(False, error.code, None)
        except (ArtifactStoreError, OSError):
            return SourceReviewFacts(False, "source_storage_unavailable", None)
        return SourceReviewFacts(
            True, "source_excerpt_truncated" if excerpt.truncated else None, excerpt
        )
