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
