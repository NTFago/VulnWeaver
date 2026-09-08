from __future__ import annotations

import asyncio
import sys
from datetime import timedelta
from typing import cast

import pytest
from sqlalchemy import func, select
from vulnweaver_contracts import (
    ArtifactKind,
    JobKind,
    JobStatus,
    PermissionMode,
    TaskResult,
    TaskStatus,
)
from vulnweaver_persistence import (
    Database,
    DatabaseSettings,
    EntityConflict,
    EntityNotFound,
    IdempotencyConflict,
    PersistenceInvariantError,
)
from vulnweaver_persistence.models import jobs, outbox_events

from tests.persistence.factories import (
    artifact,
    artifact_version,
    job,
    job_event,
    project,
    task,
    task_event,
)

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


@pytest.fixture(scope="module")
def seeded_database_url(persistence_database_url: str) -> str:
    async def seed() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        try:
            async with database.transaction() as repositories:
                await repositories.projects.add(project())
                await repositories.artifacts.add(artifact())
                await repositories.artifacts.add_version(artifact_version())
                await repositories.tasks.create(task())
                initial_job = job()
                result = await repositories.jobs.enqueue_with_outbox(
                    initial_job, job_event(initial_job)
                )
                assert result.created
        finally:
            await database.dispose()

    asyncio.run(seed())
    return persistence_database_url


def test_job_and_outbox_commit_atomically_and_retry_idempotently(
    seeded_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(seeded_database_url))
        try:
            retry_job = job("job:t03-retry")
            retry_event = job_event(retry_job, "event:t03-retry")
            async with database.transaction() as repositories:
                retry = await repositories.jobs.enqueue_with_outbox(retry_job, retry_event)
                assert not retry.created
                assert retry.job["id"] == "job:t03"
                assert retry.event["event_id"] == "event:t03"
                pending = await repositories.outbox.pending()
                assert "event:t03" in {
                    message.event["event_id"] for message in pending
                }
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_idempotency_key_reuse_with_different_request_is_rejected(
    seeded_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(seeded_database_url))
        try:
            conflicting_job = job(
                "job:t03-conflict",
                idempotency_key="job:t03-key",
                kind=JobKind.REVIEW,
            )
            with pytest.raises(IdempotencyConflict) as captured:
                async with database.transaction() as repositories:
                    await repositories.jobs.enqueue_with_outbox(
                        conflicting_job,
                        job_event(conflicting_job, "event:t03-conflict"),
                    )
            assert captured.value.code == "idempotency_conflict"
            assert "idempotency_key" in captured.value.details
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_outbox_conflict_rolls_back_the_new_job(seeded_database_url: str) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(seeded_database_url))
        try:
            async with database.engine.connect() as connection:
                jobs_before = await connection.scalar(select(func.count()).select_from(jobs))
                events_before = await connection.scalar(
                    select(func.count()).select_from(outbox_events)
                )
            second_job = job("job:t03-rollback", idempotency_key="job:t03-rollback-key")
            duplicate_event = job_event(second_job, "event:t03")
            with pytest.raises(EntityConflict):
                async with database.transaction() as repositories:
                    await repositories.jobs.enqueue_with_outbox(second_job, duplicate_event)

            async with database.transaction() as repositories:
                with pytest.raises(EntityNotFound):
                    await repositories.jobs.get(second_job["id"])
            async with database.engine.connect() as connection:
                job_count = await connection.scalar(select(func.count()).select_from(jobs))
                event_count = await connection.scalar(
                    select(func.count()).select_from(outbox_events)
                )
                assert job_count == jobs_before
                assert event_count == events_before
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_unpublished_event_is_replayed_until_marked_published(
    seeded_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(seeded_database_url))
        try:
            replay_job = job("job:t03-replay", idempotency_key="job:t03-replay-key")
            replay_event = job_event(replay_job, "event:t03-replay")
            async with database.transaction() as repositories:
                await repositories.jobs.enqueue_with_outbox(replay_job, replay_event)
                assert await repositories.outbox.mark_failed(
                    "event:t03-replay",
                    error={"code": "redis_unavailable", "retryable": True},
                    retry_after=timedelta(0),
                )
            async with database.transaction() as repositories:
                pending = await repositories.outbox.pending()
                replay = next(
                    message
                    for message in pending
                    if message.event["event_id"] == "event:t03-replay"
                )
                assert replay.publish_attempts == 1
                assert await repositories.outbox.mark_published("event:t03-replay")
            async with database.transaction() as repositories:
                pending_ids = {
                    message.event["event_id"]
                    for message in await repositories.outbox.pending()
                }
                assert "event:t03-replay" not in pending_ids
                assert not await repositories.outbox.mark_published("event:t03-replay")
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_task_idempotency_and_artifact_digest_deduplication(
    seeded_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(seeded_database_url))
        try:
            async with database.transaction() as repositories:
                task_retry = task("task:t03-retry")
                task_result = await repositories.tasks.create(task_retry)
                assert not task_result.created
                assert task_result.value["id"] == "task:t03"

                duplicate_version = artifact_version("artifact-version:t03-retry")
                version_result = await repositories.artifacts.add_version(duplicate_version)
                assert not version_result.created
                assert version_result.value["id"] == "artifact-version:t03"
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_concurrent_task_cancellation_has_a_single_state_transition(
    persistence_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        project_id = "project:cancel-race"
        artifact_id = "artifact:cancel-race"
        version_id = "artifact-version:cancel-race"
        task_id = "task:cancel-race"
        try:
            async with database.transaction() as repositories:
                await repositories.projects.add(project(project_id))
                await repositories.artifacts.add(
                    artifact(
                        artifact_id,
                        project_id=project_id,
                        current_version_id=version_id,
                    )
                )
                await repositories.artifacts.add_version(
                    artifact_version(version_id, artifact_id=artifact_id)
                )
                await repositories.tasks.create(
                    task(
                        task_id,
                        project_id=project_id,
                        artifact_version_ids=[version_id],
                        idempotency_key="task:cancel-race-key",
                    )
                )

            async def cancel_once() -> bool:
                async with database.transaction() as repositories:
                    return (await repositories.tasks.cancel(task_id)).changed

            changed = await asyncio.gather(cancel_once(), cancel_once())
            assert sorted(changed) == [False, True]
            async with database.transaction() as repositories:
                assert (await repositories.tasks.get(task_id))["status"] is TaskStatus.CANCELLED
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_repositories_accept_schema_valid_string_enum_values(
    persistence_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        project_id = "project:t03-string-enums"
        artifact_id = "artifact:t03-string-enums"
        version_id = "artifact-version:t03-string-enums"
        task_id = "task:t03-string-enums"
        job_id = "job:t03-string-enums"

        raw_project = project(project_id)
        raw_project["permission_mode"] = cast(
            PermissionMode, "request_permission"
        )
        raw_artifact = artifact(
            artifact_id,
            project_id=project_id,
            current_version_id=version_id,
        )
        raw_artifact["kind"] = cast(ArtifactKind, "source_archive")
        raw_task = task(
            task_id,
            project_id=project_id,
            artifact_version_ids=[version_id],
            idempotency_key="task:t03-string-enums-key",
        )
        raw_task["status"] = cast(TaskStatus, "completed")
        raw_task["result"] = cast(TaskResult, "success")
        raw_job = job(
            job_id,
            task_id=task_id,
            idempotency_key="job:t03-string-enums-key",
        )
        raw_job["kind"] = cast(JobKind, "source_analysis")
        raw_job["status"] = cast(JobStatus, "pending")

        try:
            async with database.transaction() as repositories:
                await repositories.projects.add(raw_project)
                await repositories.artifacts.add(raw_artifact)
                await repositories.artifacts.add_version(
                    artifact_version(version_id, artifact_id=artifact_id)
                )
                await repositories.tasks.create(raw_task)
                await repositories.jobs.enqueue_with_outbox(
                    raw_job,
                    job_event(raw_job, "event:t03-string-enums"),
                )

                stored_project = await repositories.projects.get(project_id)
                stored_artifact = await repositories.artifacts.get(artifact_id)
                stored_task = await repositories.tasks.get(task_id)
                stored_job = await repositories.jobs.get(job_id)

            assert stored_project["permission_mode"] is PermissionMode.REQUEST_PERMISSION
            assert stored_artifact["kind"] is ArtifactKind.SOURCE_ARCHIVE
            assert stored_task["status"] is TaskStatus.COMPLETED
            assert stored_task["result"] is TaskResult.SUCCESS
            assert stored_job["kind"] is JobKind.SOURCE_ANALYSIS
            assert stored_job["status"] is JobStatus.PENDING
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_duplicate_old_content_does_not_move_current_version_backward(
    persistence_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        project_id = "project:t04-version-order"
        artifact_id = "artifact:t04-version-order"
        first_id = "artifact-version:t04-version-order-1"
        second_id = "artifact-version:t04-version-order-2"
        try:
            async with database.transaction() as repositories:
                await repositories.projects.add(project(project_id))
                await repositories.artifacts.add(
                    artifact(
                        artifact_id,
                        project_id=project_id,
                        current_version_id=first_id,
                    )
                )
                await repositories.artifacts.add_version(
                    artifact_version(first_id, artifact_id=artifact_id)
                )
                await repositories.artifacts.add_version(
                    artifact_version(
                        second_id,
                        artifact_id=artifact_id,
                        digest_character="b",
                    )
                )
                duplicate = await repositories.artifacts.add_version(
                    artifact_version(
                        "artifact-version:t04-version-order-retry",
                        artifact_id=artifact_id,
                    )
                )
                stored_artifact = await repositories.artifacts.get(artifact_id)

            assert not duplicate.created
            assert duplicate.value["id"] == first_id
            assert stored_artifact["current_version_id"] == second_id
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_event_must_match_job_before_any_write(seeded_database_url: str) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(seeded_database_url))
        try:
            invalid_job = job("job:t03-invalid", idempotency_key="job:t03-invalid-key")
            invalid_event = job_event(invalid_job, "event:t03-invalid")
            invalid_event["payload"]["task_id"] = "task:other"
            with pytest.raises(PersistenceInvariantError):
                async with database.transaction() as repositories:
                    await repositories.jobs.enqueue_with_outbox(invalid_job, invalid_event)
            async with database.transaction() as repositories:
                with pytest.raises(EntityNotFound):
                    await repositories.jobs.get(invalid_job["id"])
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_database_healthcheck(seeded_database_url: str) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(seeded_database_url))
        try:
            await database.healthcheck()
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_task_events_are_append_only_and_type_restricted(
    seeded_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(seeded_database_url))
        try:
            event = task_event()
            async with database.transaction() as repositories:
                await repositories.task_events.append(event)

            duplicate_sequence = task_event(identifier="task-event:t03-duplicate")
            with pytest.raises(EntityConflict):
                async with database.transaction() as repositories:
                    await repositories.task_events.append(duplicate_sequence)

            with pytest.raises(ValueError, match="only accepts"):
                async with database.transaction() as repositories:
                    await repositories.task_events.append(job_event(job()))

            mismatched = task_event(identifier="task-event:t03-mismatched", sequence=1)
            mismatched["payload"]["task_id"] = "task:other"
            with pytest.raises(PersistenceInvariantError):
                async with database.transaction() as repositories:
                    await repositories.task_events.append(mismatched)
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_repository_conflicts_remain_structured(seeded_database_url: str) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(seeded_database_url))
        try:
            async with database.transaction() as repositories:
                stored = await repositories.projects.get("project:t03")
                assert stored["permission_mode"].value == "request_permission"
                with pytest.raises(EntityNotFound):
                    await repositories.tasks.get("task:missing")

            with pytest.raises(EntityConflict) as duplicate_project:
                async with database.transaction() as repositories:
                    await repositories.projects.add(project())
            assert duplicate_project.value.as_dict() == {
                "code": "entity_conflict",
                "message": "project identifier already exists",
                "retryable": False,
                "details": {"project_id": "project:t03"},
            }

            conflicting_task = task("task:t03-conflicting-request")
            conflicting_task["artifact_version_ids"] = ["artifact-version:other"]
            with pytest.raises(IdempotencyConflict):
                async with database.transaction() as repositories:
                    await repositories.tasks.create(conflicting_task)

            conflicting_version = artifact_version(
                "artifact-version:t03", digest_character="b"
            )
            with pytest.raises(EntityConflict):
                async with database.transaction() as repositories:
                    await repositories.artifacts.add_version(conflicting_version)

            conflicting_job = job("job:t03", idempotency_key="job:t03-different-key")
            with pytest.raises(EntityConflict):
                async with database.transaction() as repositories:
                    await repositories.jobs.enqueue_with_outbox(
                        conflicting_job,
                        job_event(conflicting_job, "event:t03-different-key"),
                    )
        finally:
            await database.dispose()

    asyncio.run(scenario())


@pytest.mark.parametrize("limit", [0, 1001])
def test_outbox_batch_size_has_a_safe_bound(
    seeded_database_url: str, limit: int
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(seeded_database_url))
        try:
            with pytest.raises(ValueError, match="between 1 and 1000"):
                async with database.transaction() as repositories:
                    await repositories.outbox.pending(limit=limit)
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_outbox_claim_skips_rows_locked_by_another_dispatcher(
    seeded_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(seeded_database_url))
        try:
            claimed_job = job(
                "job:t05-claim", idempotency_key="job:t05-claim-key"
            )
            async with database.transaction() as repositories:
                await repositories.jobs.enqueue_with_outbox(
                    claimed_job, job_event(claimed_job, "event:t05-claim")
                )

            async with database.transaction() as first:
                first_batch = await first.outbox.claim_pending(limit=1000)
                first_ids = {message.event["event_id"] for message in first_batch}
                assert "event:t05-claim" in first_ids
                async with database.transaction() as second:
                    second_batch = await second.outbox.claim_pending(limit=1000)
                    second_ids = {
                        message.event["event_id"] for message in second_batch
                    }
                    assert first_ids.isdisjoint(second_ids)
        finally:
            await database.dispose()

    asyncio.run(scenario())
