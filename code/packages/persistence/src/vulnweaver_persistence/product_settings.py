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

    async def get_row(self) -> dict[str, object]:
        """Return the raw row (values plus updated_at) for change detection."""

        row = (
            (
                await self._connection.execute(
                    select(
                        product_settings.c["values"], product_settings.c.updated_at
                    ).where(product_settings.c.id == "installation")
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            return {"values": {}, "updated_at": None}
        return {"values": dict(row["values"]), "updated_at": row["updated_at"]}

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
