"""Structured API error mapping."""
# pyright: reportUnusedFunction=false

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from vulnweaver_artifact_store import ArtifactStoreError
from vulnweaver_contracts import ContractValidationError
from vulnweaver_domain import IdempotencyKeyError
from vulnweaver_persistence import PersistenceError

from vulnweaver_api.auth import (
    AuthenticationFailed,
    PasswordChangeRequired,
    PasswordPolicyViolation,
)
from vulnweaver_api.middleware import new_identifier
from vulnweaver_api.schemas import ErrorDetail, ErrorResponse
from vulnweaver_api.uploads import UploadTooLarge

LOGGER = logging.getLogger(__name__)


class ApiInputError(ValueError):
    def __init__(self, code: str, message: str, field: str) -> None:
        self.code = code
        self.message = message
        self.field = field
        super().__init__(message)


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, error: RequestValidationError) -> JSONResponse:
        details = [
            ErrorDetail(field=".".join(str(part) for part in item["loc"]), reason=item["msg"])
            for item in error.errors()
        ]
        return _error(
            request,
            422,
            "request_validation_failed",
            "request validation failed",
            details=details,
        )

    @app.exception_handler(ContractValidationError)
    async def contract_error(request: Request, error: ContractValidationError) -> JSONResponse:
        return _error(
            request,
            422,
            "contract_validation_failed",
            "request does not satisfy the public contract",
            details=[ErrorDetail(field=error.definition, reason=item) for item in error.errors],
        )

    @app.exception_handler(ApiInputError)
    async def input_error(request: Request, error: ApiInputError) -> JSONResponse:
        return _error(
            request,
            422,
            error.code,
            error.message,
            details=[ErrorDetail(field=error.field, reason=error.message)],
        )

    @app.exception_handler(AuthenticationFailed)
    async def auth_error(request: Request, error: AuthenticationFailed) -> JSONResponse:
        return _error(request, 401, "authentication_failed", str(error))

    @app.exception_handler(PasswordChangeRequired)
    async def password_change_error(
        request: Request, error: PasswordChangeRequired
    ) -> JSONResponse:
        return _error(request, 403, "password_change_required", str(error))

    @app.exception_handler(PasswordPolicyViolation)
    async def password_policy_error(
        request: Request, error: PasswordPolicyViolation
    ) -> JSONResponse:
        return _error(request, 422, "password_policy_violation", str(error))

    @app.exception_handler(IdempotencyKeyError)
    async def idempotency_key_error(
        request: Request, error: IdempotencyKeyError
    ) -> JSONResponse:
        return _error(request, 422, "invalid_idempotency_key", str(error))

    @app.exception_handler(UploadTooLarge)
    async def upload_too_large(request: Request, error: UploadTooLarge) -> JSONResponse:
        return _error(request, 413, "artifact_too_large", str(error))

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, error: StarletteHTTPException) -> JSONResponse:
        return _error(request, error.status_code, "http_error", str(error.detail))

    @app.exception_handler(PersistenceError)
    async def persistence_error(request: Request, error: PersistenceError) -> JSONResponse:
        status = (
            404
            if error.code == "entity_not_found"
            else 409
            if error.code in {"entity_conflict", "idempotency_conflict"}
            else 500
        )
        details = [
            ErrorDetail(field=str(key), reason=str(value)) for key, value in error.details.items()
        ]
        return _error(
            request,
            status,
            error.code,
            error.message,
            retryable=error.retryable,
            details=details,
        )

    @app.exception_handler(ArtifactStoreError)
    async def artifact_error(request: Request, error: ArtifactStoreError) -> JSONResponse:
        status = (
            413
            if error.code == "artifact_too_large"
            else 404
            if error.code == "artifact_not_found"
            else 422
        )
        return _error(request, status, error.code, error.message, retryable=error.retryable)

    @app.exception_handler(Exception)
    async def unexpected_error(request: Request, error: Exception) -> JSONResponse:
        LOGGER.exception("unhandled API exception", exc_info=error)
        return _error(request, 500, "internal_error", "an unexpected internal error occurred")


def _error(
    request: Request,
    status: int,
    code: str,
    message: str,
    *,
    retryable: bool = False,
    details: list[ErrorDetail] | None = None,
) -> JSONResponse:
    correlation_id = getattr(request.state, "correlation_id", new_identifier("request"))
    body = ErrorResponse(
        error_code=code,
        message=message,
        correlation_id=correlation_id,
        retryable=retryable,
        details=details or [],
    )
    return JSONResponse(
        status_code=status,
        content=body.model_dump(mode="json"),
        headers={"X-Correlation-ID": correlation_id},
    )
