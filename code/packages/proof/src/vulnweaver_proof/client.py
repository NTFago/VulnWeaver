"""Structured client for the isolated Sandbox Runner service."""

from __future__ import annotations

import asyncio
from typing import TypeGuard, cast
from urllib.parse import urlparse

import httpx
from vulnweaver_contracts import SandboxRequest, SandboxResult, validate_contract


class SandboxRunnerClient:
    def __init__(
        self,
        base_url: str,
        *,
        timeout_seconds: float = 30.0,
        bearer_token: str | None = None,
    ) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("sandbox runner URL must use http or https")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("sandbox runner URL must not contain credentials or query data")
        if timeout_seconds <= 0 or timeout_seconds > 600:
            raise ValueError("sandbox runner timeout must be between 0 and 600 seconds")
        if bearer_token is not None and not bearer_token:
            raise ValueError("sandbox bearer token must not be empty")
        self._url = base_url.rstrip("/") + "/v1/sandbox/runs"
        self._base = base_url.rstrip("/")
        self._timeout = timeout_seconds
        self._headers = {"Authorization": f"Bearer {bearer_token}"} if bearer_token else {}

    async def tool_digest(self, tool_name: str, tool_version: str) -> str | None:
        """Read a digest registered by the Runner without accessing Docker."""
        payload = await self._get_json(f"/v1/tools/{tool_name}/{tool_version}")
        if payload is None:
            return None
        digest = payload.get("image_digest")
        return digest if _is_digest(digest) else None

    async def registered_tools(self) -> dict[tuple[str, str], str]:
        """List every digest-pinned tool identity the Runner enforces."""
        payload = await self._get_json("/v1/tools")
        if payload is None:
            return {}
        entries = payload.get("tools")
        if not isinstance(entries, list):
            return {}
        tools: dict[tuple[str, str], str] = {}
        for entry in cast(list[object], entries):
            if not isinstance(entry, dict):
                continue
            item = cast(dict[str, object], entry)
            name, version, digest = (
                item.get("tool_name"),
                item.get("tool_version"),
                item.get("image_digest"),
            )
            if isinstance(name, str) and isinstance(version, str) and _is_digest(digest):
                tools[(name, version)] = digest
        return tools

    async def _get_json(self, path: str) -> dict[str, object] | None:
        try:
            async with httpx.AsyncClient(timeout=self._timeout, follow_redirects=False) as client:
                response = await client.get(f"{self._base}{path}", headers=self._headers)
            response.raise_for_status()
            payload = response.json()
            return cast(dict[str, object], payload) if isinstance(payload, dict) else None
        except (httpx.HTTPError, ValueError, TypeError):
            return None

    async def run(
        self, request: SandboxRequest, cancellation: asyncio.Event
    ) -> SandboxResult:
        validate_contract("SandboxRequest", request)
        task = asyncio.create_task(self._request(request))
        cancelled = asyncio.create_task(cancellation.wait())
        done, _ = await asyncio.wait({task, cancelled}, return_when=asyncio.FIRST_COMPLETED)
        if cancelled in done and cancelled.result():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            return cast(SandboxResult, _failure(request["id"], "sandbox.cancelled"))
        cancelled.cancel()
        await asyncio.gather(cancelled, return_exceptions=True)
        return await task

    async def _request(self, request: SandboxRequest) -> SandboxResult:
        try:
            async with httpx.AsyncClient(timeout=self._timeout, follow_redirects=False) as client:
                response = await client.post(self._url, json=request, headers=self._headers)
            response.raise_for_status()
            result = cast(SandboxResult, response.json())
            validate_contract("SandboxResult", result)
            if result["request_id"] != request["id"]:
                raise ValueError("sandbox runner response request id mismatch")
            return result
        except (httpx.HTTPError, ValueError, TypeError) as error:
            return cast(
                SandboxResult,
                _failure(request["id"], "sandbox.transport_failed", str(error)),
            )


def _is_digest(value: object) -> TypeGuard[str]:
    return isinstance(value, str) and value.startswith("sha256:")


def _failure(request_id: str, code: str, detail: str = "") -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "request_id": request_id,
        "status": "failed",
        "exit_code": None,
        "stdout_ref": None,
        "stderr_ref": None,
        "outputs": [],
        "resource_usage": {
            "duration_millis": 0,
            "cpu_millis": 0,
            "memory_bytes": 0,
            "output_bytes": 0,
        },
        "failure": {
            "code": code,
            "kind": "dependency",
            "message": "sandbox runner request failed",
            "retryable": code == "sandbox.transport_failed",
            "details": {"error": detail[:512]},
        },
    }
