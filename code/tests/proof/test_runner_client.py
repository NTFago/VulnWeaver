"""Client-side contract of the Runner digest surface.

These exercise the real HTTP path with a local server rather than a transport
stub, because the behaviour under test is the wire contract: bearer
authorization, exact-identity lookup, and discovery of registered tools.
"""

from __future__ import annotations

import asyncio
import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from vulnweaver_proof import SandboxRunnerClient

_DIGEST = "sha256:" + "a" * 64
_TOOLS = {
    ("afl-casr", "1.0.0"): _DIGEST,
    ("proof-tool", "1.0.0"): "sha256:" + "b" * 64,
}


class _RunnerHandler(BaseHTTPRequestHandler):
    token: str | None = None

    current_digest: str = _DIGEST
    seen_digests: list[str] = []

    def do_POST(self) -> None:  # noqa: N802 - http.server naming
        length = int(self.headers.get("Content-Length") or 0)
        request = json.loads(self.rfile.read(length) or b"{}")
        self.seen_digests.append(request.get("image_digest"))
        if request.get("image_digest") != self.current_digest:
            self._send(
                200,
                {
                    "schema_version": "1.0.0",
                    "request_id": request.get("id"),
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
                        "code": "sandbox.image_identity_mismatch",
                        "kind": "policy",
                        "message": "sandbox image digest does not match the registered ToolSpec",
                        "retryable": False,
                        "details": {},
                    },
                },
            )
            return
        self._send(
            200,
            {
                "schema_version": "1.0.0",
                "request_id": request.get("id"),
                "status": "succeeded",
                "exit_code": 0,
                "stdout_ref": None,
                "stderr_ref": None,
                "outputs": [],
                "resource_usage": {
                    "duration_millis": 1,
                    "cpu_millis": 1,
                    "memory_bytes": 1,
                    "output_bytes": 0,
                },
                "failure": None,
            },
        )

    def do_GET(self) -> None:  # noqa: N802 - http.server naming
        if self.token is not None and self.headers.get("Authorization") != f"Bearer {self.token}":
            self._send(401, {"detail": "sandbox authorization required"})
            return
        if self.path == "/v1/tools":
            payload = {
                "tools": [
                    {"tool_name": name, "tool_version": version, "image_digest": digest}
                    for (name, version), digest in sorted(_TOOLS.items())
                ]
            }
            self._send(200, payload)
            return
        if self.path == "/v1/tools/afl-casr/1.0.0":
            self._send(
                200,
                {
                    "tool_name": "afl-casr",
                    "tool_version": "1.0.0",
                    "image_digest": self.current_digest,
                },
            )
            return
        for (name, version), digest in _TOOLS.items():
            if self.path == f"/v1/tools/{name}/{version}":
                self._send(
                    200,
                    {"tool_name": name, "tool_version": version, "image_digest": digest},
                )
                return
        self._send(404, {"detail": "tool is not registered"})

    def _send(self, status: int, payload: dict[str, object]) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        """Keep the test output quiet."""


@contextmanager
def _runner(token: str | None = None) -> Iterator[str]:
    _RunnerHandler.token = token
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RunnerHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_client_rejects_empty_bearer_token() -> None:
    with pytest.raises(ValueError):
        SandboxRunnerClient("http://127.0.0.1:1", bearer_token="")


def test_client_reads_digest_and_lists_registered_tools() -> None:
    with _runner() as url:
        client = SandboxRunnerClient(url)

        assert asyncio.run(client.tool_digest("afl-casr", "1.0.0")) == _DIGEST
        assert asyncio.run(client.tool_digest("missing", "1.0.0")) is None
        assert asyncio.run(client.registered_tools()) == _TOOLS


def test_client_authenticates_when_the_runner_pins_a_token() -> None:
    with _runner(token="runner-secret") as url:
        anonymous = SandboxRunnerClient(url)
        assert asyncio.run(anonymous.tool_digest("afl-casr", "1.0.0")) is None
        assert asyncio.run(anonymous.registered_tools()) == {}

        authenticated = SandboxRunnerClient(url, bearer_token="runner-secret")
        assert asyncio.run(authenticated.tool_digest("afl-casr", "1.0.0")) == _DIGEST
        assert asyncio.run(authenticated.registered_tools()) == _TOOLS


def test_identity_mismatch_realigns_digest_and_retries_once() -> None:
    from vulnweaver_contracts import SandboxRequest, validate_contract

    with _runner() as url:
        client = SandboxRunnerClient(url)
        stale = "sha256:" + "d" * 64
        request = SandboxRequest(
            schema_version="1.0.0",
            id="request-mismatch",
            tool_name="afl-casr",
            tool_version="1.0.0",
            image_digest=stale,
            artifact_kind="source_archive",
            input_ref="cas://sha256/" + "e" * 64,
            arguments={},
            output_file_names=[],
            resource_budget={
                "max_model_tokens": 0,
                "cpu_millis": 1,
                "memory_bytes": 1048576,
                "disk_bytes": 1048576,
                "max_tool_concurrency": 1,
                "max_dynamic_runs": 0,
                "timeout_seconds": 60,
            },
            timeout_seconds=60,
        )
        validate_contract("SandboxRequest", request)
        result = asyncio.run(client.run(request, asyncio.Event()))

        # First attempt failed with the stale digest; the client re-fetched the
        # Runner's registered digest and the retry succeeded.
        assert _RunnerHandler.seen_digests == [stale, _RunnerHandler.current_digest]
        assert result["status"] == "succeeded"
        assert result["failure"] is None


def test_client_accepts_settings_scale_runner_timeouts() -> None:
    """The client bound matches the settings schema (one day), not the old 600s.

    A binary facts pass over a large real-world sample legitimately waits
    tens of minutes, so the configurable command timeout must be expressible
    in the client that waits on the runner's response.
    """

    SandboxRunnerClient("http://127.0.0.1:1", timeout_seconds=86_400)
    with pytest.raises(ValueError):
        SandboxRunnerClient("http://127.0.0.1:1", timeout_seconds=86_401)
