"""HTTP boundary for the isolated Sandbox Runner service."""

# pyright: reportUnusedFunction=false

from __future__ import annotations

import asyncio
import hmac
from collections.abc import Callable, Mapping
from typing import cast

from fastapi import FastAPI, Header, HTTPException, Request
from vulnweaver_contracts import SandboxRequest, SandboxResult, validate_contract

from vulnweaver_sandbox_runner.runner import SandboxRunner

ToolDigests = Mapping[tuple[str, str], str] | Callable[[], Mapping[tuple[str, str], str]]


def create_sandbox_app(
    runner: SandboxRunner,
    *,
    bearer_token: str | None = None,
    tool_digests: ToolDigests | None = None,
) -> FastAPI:
    """Create the private service boundary around one configured Runner.

    ``tool_digests`` defaults to the Runner's own registry, so the served
    identities are exactly the ones the Runner will enforce.
    """

    if bearer_token is not None and not bearer_token:
        raise ValueError("sandbox bearer token must not be empty")
    app = FastAPI(title="VulnWeaver Sandbox Runner", docs_url=None, redoc_url=None)

    def current_digests() -> Mapping[tuple[str, str], str]:
        source = tool_digests if tool_digests is not None else runner.tool_digests
        return source() if callable(source) else source

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/v1/tools")
    async def list_tools(
        authorization: str | None = Header(default=None),
    ) -> dict[str, object]:
        _authorize(authorization, bearer_token)
        digests = current_digests()
        return {
            "tools": [
                {"tool_name": name, "tool_version": version, "image_digest": digest}
                for (name, version), digest in sorted(digests.items())
            ]
        }

    @app.get("/v1/tools/{tool_name}/{tool_version}")
    async def tool_digest(
        tool_name: str,
        tool_version: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, str]:
        _authorize(authorization, bearer_token)
        digest = current_digests().get((tool_name, tool_version))
        if digest is None:
            raise HTTPException(status_code=404, detail="tool is not registered")
        return {"tool_name": tool_name, "tool_version": tool_version, "image_digest": digest}

    @app.post("/v1/sandbox/runs", response_model=None)
    async def run_sandbox(
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> SandboxResult:
        _authorize(authorization, bearer_token)
        try:
            payload = cast(SandboxRequest, await request.json())
            validate_contract("SandboxRequest", payload)
        except (ValueError, TypeError) as error:
            raise HTTPException(status_code=422, detail="invalid sandbox request") from error
        cancellation = asyncio.Event()
        disconnect = asyncio.create_task(_watch_disconnect(request, cancellation))
        try:
            return await runner.run(payload, cancellation)
        finally:
            disconnect.cancel()
            await asyncio.gather(disconnect, return_exceptions=True)

    return app


def _authorize(authorization: str | None, expected: str | None) -> None:
    if expected is None:
        return
    supplied = authorization or ""
    prefix = "Bearer "
    if not supplied.startswith(prefix) or not hmac.compare_digest(
        supplied[len(prefix) :], expected
    ):
        raise HTTPException(status_code=401, detail="sandbox authorization required")


async def _watch_disconnect(request: Request, cancellation: asyncio.Event) -> None:
    while True:
        if await request.is_disconnected():
            cancellation.set()
            return
        await asyncio.sleep(0.25)
