"""Concurrency-safe idempotency records for HTTP domain mutations."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import RowMapping, select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncConnection

from vulnweaver_persistence.errors import IdempotencyConflict
from vulnweaver_persistence.models import api_requests


@dataclass(frozen=True, slots=True)
class ApiRequestRecord:
    scope: str
    idempotency_key: str
    request_fingerprint: str
    resource_type: str
    resource_id: str
    response_status: int


class ApiRequestRepository:
    def __init__(self, connection: AsyncConnection) -> None:
        self._connection = connection

    async def lock(self, *, scope: str, key: str) -> None:
        await self._connection.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:value, 0))"),
            {"value": f"{scope}\x1f{key}"},
        )

    async def get(self, *, scope: str, key: str) -> ApiRequestRecord | None:
        row = (
            (
                await self._connection.execute(
                    select(api_requests).where(
                        api_requests.c.scope == scope,
                        api_requests.c.idempotency_key == key,
                    )
                )
            )
            .mappings()
            .one_or_none()
        )
        return None if row is None else _record(row)

    async def add(
        self,
        *,
        scope: str,
        key: str,
        fingerprint: str,
        resource_type: str,
        resource_id: str,
        response_status: int,
    ) -> ApiRequestRecord:
        await self._connection.execute(
            insert(api_requests)
            .values(
                scope=scope,
                idempotency_key=key,
                request_fingerprint=fingerprint,
                resource_type=resource_type,
                resource_id=resource_id,
                response_status=response_status,
            )
            .on_conflict_do_nothing()
        )
        stored = await self.get(scope=scope, key=key)
        assert stored is not None
        if stored.request_fingerprint != fingerprint:
            raise IdempotencyConflict(
                "idempotency key was already used for a different API request",
                details={"scope": scope, "idempotency_key": key},
            )
        return stored


def _record(row: RowMapping) -> ApiRequestRecord:
    return ApiRequestRecord(
        scope=row["scope"],
        idempotency_key=row["idempotency_key"],
        request_fingerprint=row["request_fingerprint"],
        resource_type=row["resource_type"],
        resource_id=row["resource_id"],
        response_status=row["response_status"],
    )
