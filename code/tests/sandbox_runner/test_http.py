from typing import cast

from fastapi.testclient import TestClient
from vulnweaver_sandbox_runner import create_sandbox_app
from vulnweaver_sandbox_runner.runner import SandboxRunner

_DIGESTS = {
    ("afl-casr", "1.0.0"): "sha256:" + "a" * 64,
    ("proof-tool", "1.0.0"): "sha256:" + "b" * 64,
}
_TOKEN = {"Authorization": "Bearer runner-secret"}


class _RunnerWithDigests:
    """Stands in for a configured Runner whose registry pins tool identities."""

    def tool_digests(self) -> dict[tuple[str, str], str]:
        return dict(_DIGESTS)


def _client(**kwargs: object) -> TestClient:
    runner = cast(SandboxRunner, _RunnerWithDigests())
    return TestClient(create_sandbox_app(runner, bearer_token="runner-secret", **kwargs))  # type: ignore[arg-type]


def test_sandbox_http_boundary_requires_bearer_token() -> None:
    app = create_sandbox_app(cast(SandboxRunner, object()), bearer_token="runner-secret")
    client = TestClient(app)

    assert client.get("/health").json() == {"status": "ok"}
    response = client.post("/v1/sandbox/runs", json={}, headers={"Authorization": "Bearer wrong"})
    assert response.status_code == 401


def test_registered_tool_digests_are_served_from_the_runner_registry() -> None:
    client = _client()

    response = client.get("/v1/tools/afl-casr/1.0.0", headers=_TOKEN)
    assert response.status_code == 200
    assert response.json() == {
        "tool_name": "afl-casr",
        "tool_version": "1.0.0",
        "image_digest": _DIGESTS[("afl-casr", "1.0.0")],
    }

    assert client.get("/v1/tools/afl-casr/1.0.0").status_code == 401
    unregistered = client.get("/v1/tools/unknown-tool/1.0.0", headers=_TOKEN)
    assert unregistered.status_code == 404


def test_registered_tools_endpoint_lists_every_pinned_identity() -> None:
    client = _client()

    assert client.get("/v1/tools").status_code == 401

    payload = client.get("/v1/tools", headers=_TOKEN).json()
    assert payload == {
        "tools": [
            {
                "tool_name": "afl-casr",
                "tool_version": "1.0.0",
                "image_digest": _DIGESTS[("afl-casr", "1.0.0")],
            },
            {
                "tool_name": "proof-tool",
                "tool_version": "1.0.0",
                "image_digest": _DIGESTS[("proof-tool", "1.0.0")],
            },
        ]
    }


def test_explicit_tool_digests_override_the_runner_registry() -> None:
    override = {("afl-casr", "1.0.0"): "sha256:" + "c" * 64}
    client = _client(tool_digests=override)

    served = client.get("/v1/tools/afl-casr/1.0.0", headers=_TOKEN).json()
    assert served["image_digest"] == override[("afl-casr", "1.0.0")]
    # The override is authoritative: identities it omits are not served.
    assert client.get("/v1/tools/proof-tool/1.0.0", headers=_TOKEN).status_code == 404
