"""Programmatic Alembic entry points used by services and tests."""

from __future__ import annotations

from importlib.resources import files

from alembic import command
from alembic.config import Config


def alembic_config(database_url: str) -> Config:
    if not database_url.startswith("postgresql+psycopg://"):
        raise ValueError("migration URL must use the postgresql+psycopg driver")
    script_location = files("vulnweaver_persistence").joinpath("alembic")
    config = Config()
    config.set_main_option("script_location", str(script_location))
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    return config


def upgrade_database(database_url: str, revision: str = "head") -> None:
    command.upgrade(alembic_config(database_url), revision)


def downgrade_database(database_url: str, revision: str = "base") -> None:
    command.downgrade(alembic_config(database_url), revision)
