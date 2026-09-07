from __future__ import annotations

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect
from vulnweaver_persistence import metadata

EXPECTED_TABLES = {
    "alembic_version",
    "artifact_versions",
    "artifacts",
    "jobs",
    "outbox_events",
    "projects",
    "task_events",
    "tasks",
}


def test_migration_creates_expected_tables(persistence_database_url: str) -> None:
    engine = create_engine(persistence_database_url)
    try:
        assert set(inspect(engine).get_table_names()) == EXPECTED_TABLES
    finally:
        engine.dispose()


def test_metadata_has_no_drift_from_migration(persistence_database_url: str) -> None:
    engine = create_engine(persistence_database_url)
    try:
        with engine.connect() as connection:
            context = MigrationContext.configure(connection)
            assert compare_metadata(context, metadata) == []
    finally:
        engine.dispose()
