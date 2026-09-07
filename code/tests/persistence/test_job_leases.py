from __future__ import annotations

import asyncio
import sys
from datetime import UTC, datetime

import pytest
from sqlalchemy import update
from vulnweaver_contracts import JobStatus
from vulnweaver_persistence import (
    Database,
    DatabaseSettings,
    JobLeaseClaimOutcome,
    JobLeaseConflict,
)
from vulnweaver_persistence.models import jobs

from tests.persistence.factories import (
    artifact,
    artifact_version,
    job,
    job_event,
    project,
    task,
)

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


@pytest.fixture(scope="module")
def lease_database_url(persistence_database_url: str) -> str:
    async def seed() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        try:
            async with database.transaction() as repositories:
                await repositories.projects.add(project("project:t06"))
                await repositories.artifacts.add(
                    artifact(
                        "artifact:t06",
                        project_id="project:t06",
                        current_version_id="artifact-version:t06",
                    )
                )
                await repositories.artifacts.add_version(
                    artifact_version("artifact-version:t06", artifact_id="artifact:t06")
                )
                await repositories.tasks.create(
                    task(
                        "task:t06",
                        project_id="project:t06",
                        artifact_version_ids=["artifact-version:t06"],
                        idempotency_key="task:t06-key",
                    )
                )
        finally:
            await database.dispose()

    asyncio.run(seed())
    return persistence_database_url


async def _enqueue(database: Database, identifier: str) -> None:
    value = job(
        identifier,
        task_id="task:t06",
        idempotency_key=f"{identifier}-key",
    )
    async with database.transaction() as repositories:
        await repositories.jobs.enqueue_with_outbox(
            value,
            job_event(value, f"event:{identifier}"),
        )


def test_job_lease_claim_is_exclusive_and_same_owner_is_idempotent(
    lease_database_url: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(lease_database_url))
        try:
            await _enqueue(database, "job:t06-exclusive")
            async with database.transaction() as repositories:
                first = await repositories.jobs.claim_lease(
                    "job:t06-exclusive",
                    owner="worker:t06-a",
                    lease_seconds=60,
                    heartbeat_interval_seconds=10,
                )
            assert first.outcome is JobLeaseClaimOutcome.ACQUIRED
            assert first.job["status"] is JobStatus.RUNNING
            assert first.job["attempt"] == 1
            assert first.job["lease"] is not None
            assert first.job["lease"]["owner"] == "worker:t06-a"

            async with database.transaction() as repositories:
                busy = await repositories.jobs.claim_lease(
                    "job:t06-exclusive",
                    owner="worker:t06-b",
                    lease_seconds=60,
                    heartbeat_interval_seconds=10,
                )
                repeated = await repositories.jobs.claim_lease(
                    "job:t06-exclusive",
                    owner="worker:t06-a",
                    lease_seconds=60,
                    heartbeat_interval_seconds=10,
                )
            assert busy.outcome is JobLeaseClaimOutcome.BUSY
            assert repeated.outcome is JobLeaseClaimOutcome.ACQUIRED
            assert repeated.job["attempt"] == 1
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_job_lease_renew_release_and_attempt_limit(lease_database_url: str) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(lease_database_url))
        try:
            await _enqueue(database, "job:t06-retry")
            async with database.transaction() as repositories:
                await repositories.jobs.claim_lease(
                    "job:t06-retry",
                    owner="worker:t06-a",
                    lease_seconds=60,
                    heartbeat_interval_seconds=10,
                )
            async with database.transaction() as repositories:
                renewed = await repositories.jobs.renew_lease(
                    "job:t06-retry", owner="worker:t06-a", lease_seconds=120
                )
                assert renewed["lease"] is not None
                with pytest.raises(JobLeaseConflict):
                    await repositories.jobs.renew_lease(
                        "job:t06-retry", owner="worker:t06-other", lease_seconds=120
                    )

            async with database.transaction() as repositories:
                released = await repositories.jobs.release_lease(
                    "job:t06-retry", owner="worker:t06-a"
                )
            assert released["status"] is JobStatus.QUEUED
            assert released["lease"] is None

            async with database.transaction() as repositories:
                second = await repositories.jobs.claim_lease(
                    "job:t06-retry",
                    owner="worker:t06-b",
                    lease_seconds=60,
                    heartbeat_interval_seconds=10,
                )
                await repositories.jobs.release_lease(
                    "job:t06-retry", owner="worker:t06-b"
                )
            assert second.job["attempt"] == 2

            async with database.transaction() as repositories:
                exhausted = await repositories.jobs.claim_lease(
                    "job:t06-retry",
                    owner="worker:t06-c",
                    lease_seconds=60,
                    heartbeat_interval_seconds=10,
                )
            assert exhausted.outcome is JobLeaseClaimOutcome.EXHAUSTED
            assert exhausted.job["attempt"] == 2
            assert exhausted.job["status"] is JobStatus.QUEUED
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_expired_job_lease_can_be_taken_over(lease_database_url: str) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(lease_database_url))
        try:
            await _enqueue(database, "job:t06-takeover")
            async with database.transaction() as repositories:
                await repositories.jobs.claim_lease(
                    "job:t06-takeover",
                    owner="worker:t06-dead",
                    lease_seconds=60,
                    heartbeat_interval_seconds=10,
                )
            async with database.engine.begin() as connection:
                await connection.execute(
                    update(jobs)
                    .where(jobs.c.id == "job:t06-takeover")
                    .values(
                        lease={
                            "owner": "worker:t06-dead",
                            "expires_at": datetime(2020, 1, 1, tzinfo=UTC).isoformat(),
                            "heartbeat_interval_seconds": 10,
                        }
                    )
                )
            async with database.transaction() as repositories:
                takeover = await repositories.jobs.claim_lease(
                    "job:t06-takeover",
                    owner="worker:t06-live",
                    lease_seconds=60,
                    heartbeat_interval_seconds=10,
                )
            assert takeover.outcome is JobLeaseClaimOutcome.ACQUIRED
            assert takeover.job["attempt"] == 2
            assert takeover.job["lease"] is not None
            assert takeover.job["lease"]["owner"] == "worker:t06-live"
        finally:
            await database.dispose()

    asyncio.run(scenario())
