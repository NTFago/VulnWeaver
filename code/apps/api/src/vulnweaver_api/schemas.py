"""Versioned HTTP view models; persisted domain contracts remain v1.0.0."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginRequest(StrictModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


class PasswordChangeRequest(StrictModel):
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=12, max_length=1024)


class MeResponse(StrictModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    username: str
    must_change_password: bool


class ErrorDetail(StrictModel):
    field: str
    reason: str


class ErrorResponse(StrictModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    error_code: str
    message: str
    correlation_id: str
    retryable: bool = False
    details: list[ErrorDetail] = Field(default_factory=lambda: list[ErrorDetail]())


class CreateProjectBody(StrictModel):
    schema_version: Literal["1.0.0"]
    name: str = Field(min_length=1, max_length=256)
    input_scope: list[str] = Field(min_length=1)
    permission_mode: Literal["request_permission", "full_access"]
    exploit_validation_enabled: bool
    resource_budget: dict[str, Any]


class CreateTaskBody(StrictModel):
    schema_version: Literal["1.0.0"]
    artifact_version_ids: list[str] = Field(min_length=1)
    resource_budget: dict[str, Any]


class ArtifactDetail(StrictModel):
    artifact: dict[str, Any]
    versions: list[dict[str, Any]]


class HealthResponse(StrictModel):
    status: Literal["ok", "ready"]
