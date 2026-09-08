"""Structured failures raised by the tool registry and policy layer."""

from __future__ import annotations

from collections.abc import Mapping


class ToolRuntimeError(RuntimeError):
    """Base error with a stable code and safe structured details."""

    code = "tool_runtime_error"

    def __init__(self, message: str, *, details: Mapping[str, object] | None = None) -> None:
        self.message = message
        self.details = dict(details or {})
        super().__init__(message)

    def as_dict(self) -> dict[str, object]:
        return {"code": self.code, "message": self.message, "details": self.details}


class ToolSpecError(ToolRuntimeError):
    code = "invalid_tool_spec"


class ToolNotFound(ToolRuntimeError):
    code = "tool_not_registered"


class ToolRegistrationConflict(ToolRuntimeError):
    code = "tool_registration_conflict"


class PolicyRejected(ToolRuntimeError):
    code = "policy_denied"


class PolicyPermissionRequired(ToolRuntimeError):
    code = "permission_required"
