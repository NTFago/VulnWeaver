"""ASGI middleware for correlation and pre-parse request size limits."""

from __future__ import annotations

from typing import cast
from uuid import uuid4

from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


def new_identifier(prefix: str) -> str:
    return f"{prefix}:{uuid4().hex}"


def valid_identifier(value: str) -> bool:
    return (
        1 <= len(value) <= 128
        and value[0].isalnum()
        and all(character.isalnum() or character in "._:-" for character in value)
    )


class CorrelationIdMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in {"http", "websocket"}:
            await self._app(scope, receive, send)
            return
        supplied = Headers(scope=scope).get("X-Correlation-ID", "")
        correlation_id = supplied if valid_identifier(supplied) else new_identifier("request")
        state = scope.setdefault("state", {})
        cast(dict[str, object], state)["correlation_id"] = correlation_id

        async def send_with_correlation(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["X-Correlation-ID"] = correlation_id
            await send(message)

        await self._app(scope, receive, send_with_correlation)


class RequestBodyLimitMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        json_max_body_size: int,
        upload_max_body_size: int,
    ) -> None:
        self._app = app
        self._json_max_body_size = json_max_body_size
        self._upload_max_body_size = upload_max_body_size

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        is_upload = _is_artifact_upload(scope)
        limit = self._upload_max_body_size if is_upload else self._json_max_body_size
        content_length = _content_length(scope)
        if content_length is not None and content_length > limit:
            await self._reject(scope, receive, send)
            return
        if is_upload:
            # The upload endpoint streams and enforces this same limit while
            # writing, so a chunked body is never buffered in application memory.
            await self._app(scope, receive, send)
            return

        messages: list[Message] = []
        consumed = 0
        while True:
            message = await receive()
            messages.append(message)
            if message["type"] != "http.request":
                break
            consumed += len(message.get("body", b""))
            if consumed > limit:
                await self._reject(scope, receive, send)
                return
            if not message.get("more_body", False):
                break

        async def replay_receive() -> Message:
            if messages:
                return messages.pop(0)
            return await receive()

        await self._app(scope, replay_receive, send)

    async def _reject(self, scope: Scope, receive: Receive, send: Send) -> None:
        state = cast(dict[str, object], scope.setdefault("state", {}))
        correlation_id = str(state.get("correlation_id") or new_identifier("request"))
        response = JSONResponse(
            status_code=413,
            content={
                "schema_version": "1.0.0",
                "error_code": "request_body_too_large",
                "message": "request body exceeds the configured size limit",
                "correlation_id": correlation_id,
                "retryable": False,
                "details": [],
            },
        )
        await response(scope, receive, send)


def _content_length(scope: Scope) -> int | None:
    raw = Headers(scope=scope).get("content-length")
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _is_artifact_upload(scope: Scope) -> bool:
    if scope.get("method") != "POST":
        return False
    parts = str(scope.get("path", "")).strip("/").split("/")
    return len(parts) == 4 and parts[:2] == ["api", "projects"] and parts[3] == "artifacts"
