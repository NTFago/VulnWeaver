"""One-shot database migration command for deployment orchestration."""

from __future__ import annotations

import os

from vulnweaver_persistence import upgrade_database


def main() -> None:
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL is required")
    upgrade_database(database_url)
