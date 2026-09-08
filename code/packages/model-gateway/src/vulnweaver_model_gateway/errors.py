"""Structured model-gateway errors that never expose credentials or raw responses."""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from vulnweaver_contracts import FailureKind, JsonObject, StructuredFailure


class ModelGatewayError(RuntimeError):
    """A safe, structured error from configuration, transport, or model output."""

    code = "model_gateway_error"
    failure_kind = FailureKind.INTERNAL
    retryable = False

    def __init__(
        self,
        message: str,
        *,
        details: Mapping[str, object] | None = None,
        retryable: bool | None = None,
    ) -> None:
        self.message = message
        self.details = cast(JsonObject, dict(details or {}))
        self.attempt_decisions: tuple[tuple[str, str], ...] = ()
        if retryable is not None:
            self.retryable = retryable
        super().__init__(message)

    def as_failure(self) -> StructuredFailure:
        return StructuredFailure(
            code=self.code,
            kind=self.failure_kind,
            message=self.message,
            retryable=self.retryable,
            details=self.details,
        )


class ModelConfigurationError(ModelGatewayError):
    code = "model_configuration_error"
    failure_kind = FailureKind.VALIDATION


class ModelTransportError(ModelGatewayError):
    code = "model_transport_error"
    failure_kind = FailureKind.DEPENDENCY


class ModelProtocolError(ModelGatewayError):
    code = "model_protocol_error"
    failure_kind = FailureKind.DEPENDENCY


class ModelOutputError(ModelGatewayError):
    code = "model_output_error"
    failure_kind = FailureKind.VALIDATION


class AgentRunConflict(ModelGatewayError):
    code = "agent_run_conflict"
    failure_kind = FailureKind.INTERNAL
