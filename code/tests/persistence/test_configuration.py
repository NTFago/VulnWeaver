from __future__ import annotations

import pytest
from vulnweaver_persistence import DatabaseSettings
from vulnweaver_persistence.migrations import alembic_config


@pytest.mark.parametrize(
    "url",
    [
        "postgresql://user:password@localhost/database",
        "sqlite:///database.sqlite3",
    ],
)
def test_database_settings_require_the_psycopg_driver(url: str) -> None:
    with pytest.raises(ValueError, match=r"postgresql\+psycopg"):
        DatabaseSettings(url)
    with pytest.raises(ValueError, match=r"postgresql\+psycopg"):
        alembic_config(url)


def test_database_settings_reject_unsafe_pool_values() -> None:
    url = "postgresql+psycopg://user:password@localhost/database"
    with pytest.raises(ValueError, match="pool and timeout"):
        DatabaseSettings(url, pool_size=0)
    with pytest.raises(ValueError, match="pool and timeout"):
        DatabaseSettings(url, max_overflow=-1)
    with pytest.raises(ValueError, match="pool and timeout"):
        DatabaseSettings(url, connect_timeout_seconds=0)
