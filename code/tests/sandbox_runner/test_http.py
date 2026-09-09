from typing import cast

from fastapi.testclient import TestClient
from vulnweaver_sandbox_runner import create_sandbox_app
from vulnweaver_sandbox_runner.runner import SandboxRunner


def test_sandbox_http_boundary_requires_bearer_token() -> None:
    app = create_sandbox_app(cast(SandboxRunner, object()), bearer_token="runner-secret")
    client = TestClient(app)

    assert client.get("/health").json() == {"status": "ok"}
    response = client.post("/v1/sandbox/runs", json={}, headers={"Authorization": "Bearer wrong"})
    assert response.status_code == 401
