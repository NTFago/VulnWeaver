"""Validated API configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class ApiSettings:
    database_url: str
    artifact_store_root: Path
    upload_max_bytes: int = 512 * 1024 * 1024
    session_ttl_seconds: int = 12 * 60 * 60
    login_failure_threshold: int = 5
    login_lockout_seconds: int = 5 * 60
    max_password_concurrency: int = 2
    max_active_sessions: int = 8
    max_upload_concurrency: int = 2
    json_body_max_bytes: int = 1024 * 1024
    secure_cookie: bool = True
    tool_spec_directory: Path | None = None

    def __post_init__(self) -> None:
        if self.upload_max_bytes < 1:
            raise ValueError("upload size limit must be positive")
        if self.session_ttl_seconds < 300:
            raise ValueError("session lifetime must be at least five minutes")
        if self.login_failure_threshold < 1:
            raise ValueError("login failure threshold must be positive")
        if self.login_lockout_seconds < 1:
            raise ValueError("login lockout duration must be positive")
        if self.max_password_concurrency < 1:
            raise ValueError("password concurrency must be positive")
        if self.max_active_sessions < 1:
            raise ValueError("active session limit must be positive")
        if self.max_upload_concurrency < 1:
            raise ValueError("upload concurrency must be positive")
        if self.json_body_max_bytes < 1024:
            raise ValueError("JSON body size limit must be at least 1 KiB")

    @property
    def request_body_max_bytes(self) -> int:
        return self.upload_max_bytes

    @property
    def upload_staging_root(self) -> Path:
        return self.artifact_store_root / ".uploads"

    @classmethod
    def from_env(cls) -> ApiSettings:
        return cls(
            database_url=os.environ.get(
                "DATABASE_URL",
                "postgresql+psycopg://vulnweaver:vulnweaver_dev_only@127.0.0.1:55432/vulnweaver",
            ),
            artifact_store_root=Path(
                os.environ.get("ARTIFACT_STORE_ROOT", "/var/lib/vulnweaver/artifacts")
            ),
            upload_max_bytes=int(os.environ.get("UPLOAD_MAX_BYTES", str(512 * 1024 * 1024))),
            session_ttl_seconds=int(os.environ.get("SESSION_TTL_SECONDS", str(12 * 60 * 60))),
            login_failure_threshold=int(os.environ.get("LOGIN_FAILURE_THRESHOLD", "5")),
            login_lockout_seconds=int(os.environ.get("LOGIN_LOCKOUT_SECONDS", "300")),
            max_password_concurrency=int(os.environ.get("MAX_PASSWORD_CONCURRENCY", "2")),
            max_active_sessions=int(os.environ.get("MAX_ACTIVE_SESSIONS", "8")),
            max_upload_concurrency=int(os.environ.get("MAX_UPLOAD_CONCURRENCY", "2")),
            json_body_max_bytes=int(os.environ.get("JSON_BODY_MAX_BYTES", str(1024 * 1024))),
            secure_cookie=_boolean_env("SECURE_COOKIE", default=True),
            tool_spec_directory=_optional_path_env("TOOL_SPEC_DIRECTORY"),
        )


def _optional_path_env(name: str) -> Path | None:
    value = os.environ.get(name)
    if value is None or not value.strip():
        return None
    return Path(value.strip())


def _boolean_env(name: str, *, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes"}:
        return True
    if normalized in {"0", "false", "no"}:
        return False
    raise ValueError(f"{name} must be a boolean")
