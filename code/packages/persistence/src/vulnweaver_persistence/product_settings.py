"""Mutable, non-secret product configuration stored in PostgreSQL."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncConnection

from vulnweaver_persistence.models import product_settings


class ProductSettingsRepository:
    def __init__(self, connection: AsyncConnection) -> None:
        self._connection = connection

    async def get(self) -> dict[str, object]:
        value = await self._connection.scalar(
            select(product_settings.c["values"]).where(product_settings.c.id == "installation")
        )
        return {} if value is None else dict(value)

    async def replace(self, values: dict[str, object]) -> dict[str, object]:
        await self._connection.execute(
            insert(product_settings)
            .values(id="installation", values=values)
            .on_conflict_do_update(
                index_elements=[product_settings.c.id],
                set_={"values": values, "updated_at": func.now()},
            )
        )
        return values
