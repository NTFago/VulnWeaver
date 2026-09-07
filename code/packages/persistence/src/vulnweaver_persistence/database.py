"""Async database lifecycle and one-transaction unit of work."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from vulnweaver_persistence.repositories import Repositories


@dataclass(frozen=True, slots=True)
class DatabaseSettings:
    url: str
    echo: bool = False
    pool_size: int = 5
    max_overflow: int = 5
    connect_timeout_seconds: int = 5

    def __post_init__(self) -> None:
        if not self.url.startswith("postgresql+psycopg://"):
            raise ValueError("database URL must use the postgresql+psycopg driver")
        if self.pool_size < 1 or self.max_overflow < 0 or self.connect_timeout_seconds < 1:
            raise ValueError("database pool and timeout settings must be positive")


class Database:
    def __init__(self, settings: DatabaseSettings) -> None:
        self.engine: AsyncEngine = create_async_engine(
            settings.url,
            echo=settings.echo,
            pool_pre_ping=True,
            pool_size=settings.pool_size,
            max_overflow=settings.max_overflow,
            connect_args={"connect_timeout": settings.connect_timeout_seconds},
        )

    @asynccontextmanager
    async def transaction(self) -> AsyncGenerator[Repositories, None]:
        """Yield repositories sharing one connection and one commit boundary."""

        async with self.engine.begin() as connection:
            yield Repositories(connection)

    async def healthcheck(self) -> None:
        async with self.engine.connect() as connection:
            await connection.execute(text("SELECT 1"))

    async def dispose(self) -> None:
        await self.engine.dispose()
