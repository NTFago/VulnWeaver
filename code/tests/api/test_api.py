from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from vulnweaver_api import ApiSettings, create_app

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


@pytest.fixture
def client(persistence_database_url: str, tmp_path: Path) -> TestClient:
    password_file = tmp_path / "personal-password.txt"
    password_file.write_text("Initial-passphrase-123\n", encoding="utf-8")
    app = create_app(
        ApiSettings(
            database_url=persistence_database_url,
            artifact_store_root=tmp_path / "artifacts",
            bootstrap_password_file=password_file,
            secure_cookie=False,
            upload_max_bytes=1024 * 1024,
        )
    )
    with TestClient(app) as value:
        yield value
    engine = create_engine(persistence_database_url)
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(
                "TRUNCATE personal_sessions, personal_accounts, api_requests, task_events, "
                "outbox_events, job_attempt_failures, job_results, jobs, tasks, "
                "artifact_versions, artifacts, projects CASCADE"
            )
    finally:
        engine.dispose()


def _login_and_change_password(client: TestClient) -> str:
    existing = client.post(
        "/api/auth/login",
        json={"username": "owner", "password": "Changed-passphrase-456"},
    )
    if existing.status_code == 200:
        return existing.headers["x-csrf-token"]
    login = client.post(
        "/api/auth/login",
        json={"username": "owner", "password": "Initial-passphrase-123"},
    )
    assert login.status_code == 200
    assert login.json()["must_change_password"] is True
    assert "HttpOnly" in login.headers["set-cookie"]
    assert "SameSite=strict" in login.headers["set-cookie"]
    csrf = login.headers["x-csrf-token"]

    blocked = client.get("/api/projects")
    assert blocked.status_code == 403
    assert blocked.json()["error_code"] == "password_change_required"

    changed = client.post(
        "/api/auth/password",
        headers={"X-CSRF-Token": csrf},
        json={
            "current_password": "Initial-passphrase-123",
            "new_password": "Changed-passphrase-456",
        },
    )
    assert changed.status_code == 204
    relogin = client.post(
        "/api/auth/login",
        json={"username": "owner", "password": "Changed-passphrase-456"},
    )
    assert relogin.status_code == 200
    assert relogin.json()["must_change_password"] is False
    return relogin.headers["x-csrf-token"]


def _budget() -> dict[str, int]:
    return {
        "max_model_tokens": 1000,
        "cpu_millis": 1000,
        "memory_bytes": 64 * 1024 * 1024,
        "disk_bytes": 128 * 1024 * 1024,
        "max_tool_concurrency": 1,
        "max_dynamic_runs": 0,
        "timeout_seconds": 60,
    }


def _create_project(
    client: TestClient, csrf: str, *, key: str = "project:test-key", name: str = "Personal audit"
) -> dict[str, Any]:
    response = client.post(
        "/api/projects",
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": key},
        json={
            "schema_version": "1.0.0",
            "name": name,
            "input_scope": ["local://authorized-sample"],
            "permission_mode": "request_permission",
            "exploit_validation_enabled": False,
            "resource_budget": _budget(),
        },
    )
    assert response.status_code == 201
    return response.json()


def test_personal_login_csrf_and_project_idempotency(client: TestClient) -> None:
    assert client.get("/health/live").json() == {"status": "ok"}
    csrf = _login_and_change_password(client)
    assert client.get("/health/ready").json() == {"status": "ready"}

    missing_csrf = client.post(
        "/api/projects",
        headers={"Idempotency-Key": "project:test-key"},
        json={},
    )
    assert missing_csrf.status_code == 401

    project = _create_project(client, csrf)
    replay = _create_project(client, csrf)
    assert replay["id"] == project["id"]
    second = _create_project(client, csrf, key="project:second-key", name="Second project")
    assert second["id"] != project["id"]

    conflict = client.post(
        "/api/projects",
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": "project:test-key"},
        json={
            "schema_version": "1.0.0",
            "name": "Different request",
            "input_scope": ["local://authorized-sample"],
            "permission_mode": "request_permission",
            "exploit_validation_enabled": False,
            "resource_budget": _budget(),
        },
    )
    assert conflict.status_code == 409
    assert conflict.json()["error_code"] == "idempotency_conflict"


def test_upload_task_event_and_content_flow(client: TestClient) -> None:
    csrf = _login_and_change_password(client)
    project = _create_project(client, csrf)

    empty = client.post(
        f"/api/projects/{project['id']}/artifacts",
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": "artifact:empty-key"},
        data={"kind": "source_archive"},
        files={"file": ("empty.zip", b"", "application/zip")},
    )
    assert empty.status_code == 422
    assert empty.json()["error_code"] == "empty_artifact"

    upload = client.post(
        f"/api/projects/{project['id']}/artifacts",
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": "artifact:test-key"},
        data={"kind": "source_archive"},
        files={"file": ("sample.zip", b"PK\x03\x04harmless", "application/zip")},
    )
    assert upload.status_code == 201
    artifact = upload.json()["artifact"]
    version = upload.json()["versions"][0]

    content = client.get(f"/api/artifacts/{artifact['id']}/content")
    assert content.status_code == 200
    assert content.content == b"PK\x03\x04harmless"
    assert content.headers["etag"] == version["digest"]

    task = client.post(
        f"/api/projects/{project['id']}/tasks",
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": "task:test-key"},
        json={
            "schema_version": "1.0.0",
            "artifact_version_ids": [version["id"]],
            "resource_budget": _budget(),
        },
    )
    assert task.status_code == 201
    assert task.json()["status"] == "validating"
    task_id = task.json()["id"]

    replay = client.post(
        f"/api/projects/{project['id']}/tasks",
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": "task:test-key"},
        json={
            "schema_version": "1.0.0",
            "artifact_version_ids": [version["id"]],
            "resource_budget": _budget(),
        },
    )
    assert replay.status_code == 200
    assert replay.json()["id"] == task_id

    jobs = client.get(f"/api/tasks/{task_id}/jobs")
    assert jobs.status_code == 200
    assert len(jobs.json()) == 1
    assert jobs.json()[0]["kind"] == "validate"
    assert client.get(f"/api/projects/{project['id']}/tasks").json()[0]["id"] == task_id
    assert client.get(f"/api/tasks/{task_id}").json()["id"] == task_id

    events = client.get(f"/api/tasks/{task_id}/events?after=-1")
    assert events.status_code == 200
    assert [event["sequence"] for event in events.json()] == [0]

    with client.websocket_connect(f"/api/tasks/{task_id}/events/ws?after=-1") as socket:
        assert socket.receive_json()["sequence"] == 0

    cancelled = client.post(
        f"/api/tasks/{task_id}/cancel",
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": "cancel:test-key"},
    )
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "cancelled"
    cancel_replay = client.post(
        f"/api/tasks/{task_id}/cancel",
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": "cancel:test-key"},
    )
    assert cancel_replay.json()["status"] == "cancelled"
    assert client.get(f"/api/tasks/{task_id}/jobs").json()[0]["status"] == "cancelled"
    assert [event["sequence"] for event in client.get(f"/api/tasks/{task_id}/events").json()] == [
        0,
        1,
    ]


def test_openapi_lists_control_plane_and_cookie_auth(client: TestClient) -> None:
    document = client.get("/openapi.json")
    assert document.status_code == 200
    paths = document.json()["paths"]
    assert "/api/auth/login" in paths
    assert "/api/projects/{project_id}/artifacts" in paths
    assert "/api/projects/{project_id}/tasks" in paths
    assert "/api/tasks/{task_id}/events" in paths


def test_authentication_errors_logout_and_correlation(client: TestClient) -> None:
    anonymous = client.get("/api/projects", headers={"X-Correlation-ID": "request:browser-1"})
    assert anonymous.status_code == 401
    assert anonymous.headers["x-correlation-id"] == "request:browser-1"
    assert anonymous.json()["correlation_id"] == "request:browser-1"

    invalid = client.post(
        "/api/auth/login", json={"username": "owner", "password": "wrong-password"}
    )
    assert invalid.status_code == 401
    csrf = _login_and_change_password(client)

    me = client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["username"] == "owner"
    wrong_current = client.post(
        "/api/auth/password",
        headers={"X-CSRF-Token": csrf},
        json={"current_password": "not-current-password", "new_password": "Another-passphrase-789"},
    )
    assert wrong_current.status_code == 401
    weak = client.post(
        "/api/auth/password",
        headers={"X-CSRF-Token": csrf},
        json={"current_password": "Changed-passphrase-456", "new_password": "too-short"},
    )
    assert weak.status_code == 422

    logout = client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf})
    assert logout.status_code == 204
    assert client.get("/api/auth/me").status_code == 401


def test_project_artifact_queries_and_upload_rejections(client: TestClient) -> None:
    csrf = _login_and_change_password(client)
    project = _create_project(client, csrf)
    assert client.get("/api/projects").json()[0]["id"] == project["id"]
    assert client.get(f"/api/projects/{project['id']}").json()["name"] == "Personal audit"
    assert client.get("/api/projects/project:missing").status_code == 404

    derived = client.post(
        f"/api/projects/{project['id']}/artifacts",
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": "artifact:derived"},
        data={"kind": "derived"},
        files={"file": ("derived.bin", b"MZpayload", "application/octet-stream")},
    )
    assert derived.status_code == 422
    mismatch = client.post(
        f"/api/projects/{project['id']}/artifacts",
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": "artifact:mismatch"},
        data={"kind": "elf"},
        files={"file": ("sample.elf", b"MZpayload", "application/octet-stream")},
    )
    assert mismatch.status_code == 422
    too_large = client.post(
        f"/api/projects/{project['id']}/artifacts",
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": "artifact:large"},
        data={"kind": "source_archive"},
        files={"file": ("large.zip", b"PK\x03\x04" + b"x" * (1024 * 1024), "application/zip")},
    )
    assert too_large.status_code == 413

    upload_headers = {"X-CSRF-Token": csrf, "Idempotency-Key": "artifact:query-key"}
    upload = client.post(
        f"/api/projects/{project['id']}/artifacts",
        headers=upload_headers,
        data={"kind": "pe"},
        files={"file": ("sample.exe", b"MZharmless", "application/octet-stream")},
    )
    assert upload.status_code == 201
    artifact_id = upload.json()["artifact"]["id"]
    replay = client.post(
        f"/api/projects/{project['id']}/artifacts",
        headers=upload_headers,
        data={"kind": "pe"},
        files={"file": ("renamed.exe", b"MZharmless", "application/octet-stream")},
    )
    assert replay.json()["artifact"]["id"] == artifact_id
    conflict = client.post(
        f"/api/projects/{project['id']}/artifacts",
        headers=upload_headers,
        data={"kind": "pe"},
        files={"file": ("other.exe", b"MZdifferent", "application/octet-stream")},
    )
    assert conflict.status_code == 409
    assert client.get(f"/api/projects/{project['id']}/artifacts").json()[0]["id"] == artifact_id
    assert client.get(f"/api/projects/{project['id']}/artifacts/{artifact_id}").status_code == 200
    second_project = _create_project(
        client, csrf, key="project:artifact-owner", name="Other project"
    )
    wrong_project = client.get(f"/api/projects/{second_project['id']}/artifacts/{artifact_id}")
    assert wrong_project.status_code == 422

    elf = client.post(
        f"/api/projects/{project['id']}/artifacts",
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": "artifact:elf-key"},
        data={"kind": "elf"},
        files={"file": ("sample.elf", b"\x7fELFharmless", "application/octet-stream")},
    )
    assert elf.status_code == 201

    invalid_key = client.post(
        "/api/projects",
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": "bad key!"},
        json={
            "schema_version": "1.0.0",
            "name": "Invalid key",
            "input_scope": ["local://authorized-sample"],
            "permission_mode": "request_permission",
            "exploit_validation_enabled": False,
            "resource_budget": _budget(),
        },
    )
    assert invalid_key.status_code == 422


def test_settings_validation_and_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@db:5432/v")
    monkeypatch.setenv("ARTIFACT_STORE_ROOT", str(tmp_path / "objects"))
    monkeypatch.setenv("PERSONAL_USERNAME", "personal-user")
    monkeypatch.setenv("UPLOAD_MAX_BYTES", "4096")
    monkeypatch.setenv("SESSION_TTL_SECONDS", "600")
    monkeypatch.setenv("SECURE_COOKIE", "false")
    settings = ApiSettings.from_env()
    assert settings.personal_username == "personal-user"
    assert settings.upload_max_bytes == 4096
    assert settings.session_ttl_seconds == 600
    assert settings.secure_cookie is False

    with pytest.raises(ValueError, match="username"):
        ApiSettings(settings.database_url, tmp_path, personal_username="")
    with pytest.raises(ValueError, match="upload"):
        ApiSettings(settings.database_url, tmp_path, upload_max_bytes=0)
    with pytest.raises(ValueError, match="session"):
        ApiSettings(settings.database_url, tmp_path, session_ttl_seconds=60)


def test_repeated_login_failures_lock_personal_account(client: TestClient) -> None:
    for _ in range(5):
        response = client.post(
            "/api/auth/login", json={"username": "owner", "password": "wrong-password"}
        )
        assert response.status_code == 401
    locked = client.post(
        "/api/auth/login",
        json={"username": "owner", "password": "Initial-passphrase-123"},
    )
    assert locked.status_code == 401
    assert locked.json()["message"] == "invalid username or password"
