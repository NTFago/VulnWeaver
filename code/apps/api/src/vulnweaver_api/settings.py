"""Validated API configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class ApiSettings:
    database_url: str
    artifact_store_root: Path
    bootstrap_password_file: Path | None = None
    personal_username: str = "owner"
    upload_max_bytes: int = 512 * 1024 * 1024
    session_ttl_seconds: int = 12 * 60 * 60
    secure_cookie: bool = True

    def __post_init__(self) -> None:
        if not self.personal_username or len(self.personal_username) > 128:
            raise ValueError("personal username must contain 1-128 characters")
        if self.upload_max_bytes < 1:
            raise ValueError("upload size limit must be positive")
        if self.session_ttl_seconds < 300:
            raise ValueError("session lifetime must be at least five minutes")

    @classmethod
    def from_env(cls) -> ApiSettings:
        password_file = os.environ.get("PERSONAL_PASSWORD_FILE")
        return cls(
            database_url=os.environ.get(
                "DATABASE_URL",
                "postgresql+psycopg://vulnweaver:vulnweaver_dev_only@127.0.0.1:55432/vulnweaver",
            ),
            artifact_store_root=Path(
                os.environ.get("ARTIFACT_STORE_ROOT", "/var/lib/vulnweaver/artifacts")
            ),
            bootstrap_password_file=Path(password_file) if password_file else None,
            personal_username=os.environ.get("PERSONAL_USERNAME", "owner"),
            upload_max_bytes=int(os.environ.get("UPLOAD_MAX_BYTES", str(512 * 1024 * 1024))),
            session_ttl_seconds=int(os.environ.get("SESSION_TTL_SECONDS", str(12 * 60 * 60))),
            secure_cookie=os.environ.get("SECURE_COOKIE", "true").lower() == "true",
        )
