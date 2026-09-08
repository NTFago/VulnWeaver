from __future__ import annotations

import os
import re
import uuid
from collections.abc import Iterator

import pytest
from redis import Redis
from redis.exceptions import RedisError
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import OperationalError
from vulnweaver_persistence import downgrade_database, upgrade_database

_SAFE_TEST_DATABASE = re.compile(r"^vulnweaver_test_[0-9a-f]{12}$")


@pytest.fixture(scope="session")
def persistence_database_url() -> Iterator[str]:
    admin_url = os.environ.get(
        "VULNWEAVER_TEST_ADMIN_DATABASE_URL",
        "postgresql+psycopg://vulnweaver:vulnweaver_dev_only@127.0.0.1:55432/postgres",
    )
    database_name = f"vulnweaver_test_{uuid.uuid4().hex[:12]}"
    assert _SAFE_TEST_DATABASE.fullmatch(database_name)
    admin_engine = create_engine(admin_url, isolation_level="AUTOCOMMIT", pool_pre_ping=True)
    try:
        with admin_engine.connect() as connection:
            connection.exec_driver_sql(f'CREATE DATABASE "{database_name}"')
    except OperationalError as error:
        admin_engine.dispose()
        pytest.skip(f"PostgreSQL integration environment is unavailable: {error}")

    test_url = make_url(admin_url).set(database=database_name).render_as_string(
        hide_password=False
    )
    try:
        upgrade_database(test_url)
        yield test_url
        downgrade_database(test_url)
    finally:
        with admin_engine.connect() as connection:
            connection.execute(
                text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = :database_name AND pid <> pg_backend_pid()"
                ),
                {"database_name": database_name},
            )
            connection.exec_driver_sql(f'DROP DATABASE IF EXISTS "{database_name}"')
        admin_engine.dispose()


@pytest.fixture(scope="session")
def redis_url() -> Iterator[str]:
    url = os.environ.get("VULNWEAVER_TEST_REDIS_URL", "redis://127.0.0.1:56379/15")
    client = Redis.from_url(url, decode_responses=True, socket_timeout=1)
    try:
        client.ping()
    except RedisError as error:
        client.close()
        pytest.skip(f"Redis integration environment is unavailable: {error}")
    client.close()
    yield url


@pytest.fixture
def redis_namespace(redis_url: str) -> Iterator[str]:
    namespace = f"vulnweaver_test_{uuid.uuid4().hex[:12]}"
    yield namespace
    client = Redis.from_url(redis_url, decode_responses=True, socket_timeout=1)
    keys = list(client.scan_iter(match=f"{{{namespace}}}:*", count=100))
    if keys:
        client.delete(*keys)
    client.close()
