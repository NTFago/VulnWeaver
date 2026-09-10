"""Project budgets are inert bookkeeping resolved server-side (ADR-025).

Compute-resource gating was removed: the server stores an effectively unbounded
budget row, ignores client-supplied numbers, and task creation accepts an
omitted budget. These tests pin the new behavior against the real API.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from vulnweaver_api import ApiSettings, create_app
from vulnweaver_api.budgets import UNBOUNDED_RESOURCE_BUDGET, resolve_project_budget

SHIPPED_TOOL_SPECS = Path(__file__).resolve().parents[2] / "deploy" / "tool-specs"


def test_resolved_budget_is_the_unbounded_constant() -> None:
    assert resolve_project_budget() is UNBOUNDED_RESOURCE_BUDGET
    # max_model_tokens 0 is the "no output cap" convention consumed by model callers.
    assert UNBOUNDED_RESOURCE_BUDGET["max_model_tokens"] == 0
    assert UNBOUNDED_RESOURCE_BUDGET["max_dynamic_runs"] > 0
    assert UNBOUNDED_RESOURCE_BUDGET["timeout_seconds"] > 0


@pytest.fixture
def spec_aware_client(persistence_database_url: str, tmp_path: Path) -> TestClient:
    """An API configured with the shipped tool specs, i.e. the real deployment shape."""

    app = create_app(
        ApiSettings(
            database_url=persistence_database_url,
            artifact_store_root=tmp_path / "artifacts",
            secure_cookie=False,
            tool_spec_directory=SHIPPED_TOOL_SPECS,
        )
    )
    with TestClient(app) as value:
        yield value
    engine = create_engine(persistence_database_url)
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(
                "TRUNCATE product_settings, personal_sessions, personal_accounts, "
                "api_requests, task_events, "
                "outbox_events, job_attempt_failures, job_results, jobs, tasks, "
                "artifact_versions, artifacts, projects CASCADE"
            )
    finally:
        engine.dispose()


def _register(client: TestClient) -> str:
    response = client.post(
        "/api/auth/register",
        json={
            "schema_version": "1.0.0",
            "username": "owner",
            "password": "Changed-passphrase-456",
        },
    )
    assert response.status_code == 201
    return str(response.json()["csrf_token"])


def _create_project(client: TestClient, csrf: str, budget: dict[str, int] | None) -> object:
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "name": "Budget audit",
        "input_scope": ["local://authorized-sample"],
        "permission_mode": "request_permission",
        "exploit_validation_enabled": False,
    }
    if budget is not None:
        payload["resource_budget"] = budget
    return client.post(
        "/api/projects",
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": "project:budget-audit"},
        json=payload,
    )


def test_project_without_a_budget_stores_the_unbounded_row(
    spec_aware_client: TestClient,
) -> None:
    csrf = _register(spec_aware_client)
    response = _create_project(spec_aware_client, csrf, None)
    assert response.status_code == 201
    assert response.json()["resource_budget"] == dict(UNBOUNDED_RESOURCE_BUDGET)


def test_client_supplied_budgets_are_ignored(
    spec_aware_client: TestClient,
) -> None:
    csrf = _register(spec_aware_client)
    tiny = {**dict(UNBOUNDED_RESOURCE_BUDGET), "cpu_millis": 1, "max_dynamic_runs": 0}
    response = _create_project(spec_aware_client, csrf, tiny)
    assert response.status_code == 201
    # The stored row stays the unbounded constant; nothing downstream can gate on it.
    assert response.json()["resource_budget"] == dict(UNBOUNDED_RESOURCE_BUDGET)


def test_task_creation_accepts_an_omitted_budget(spec_aware_client: TestClient) -> None:
    csrf = _register(spec_aware_client)
    project = _create_project(spec_aware_client, csrf, None)
    assert project.status_code == 201  # type: ignore[attr-defined]
    project_id = str(project.json()["id"])  # type: ignore[attr-defined]

    upload = spec_aware_client.post(
        f"/api/projects/{project_id}/artifacts?kind=source_archive",
        headers={
            "X-CSRF-Token": csrf,
            "Idempotency-Key": "artifact:budget-audit",
            "X-Artifact-Filename": "sample.zip",
            "Content-Type": "application/octet-stream",
        },
        content=b"PK\x03\x04AUTHORIZED-SAMPLE",
    )
    assert upload.status_code == 201
    version_id = str(upload.json()["artifact"]["current_version_id"])

    task = spec_aware_client.post(
        f"/api/projects/{project_id}/tasks",
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": "task:budget-audit"},
        json={
            "schema_version": "1.0.0",
            "artifact_version_ids": [version_id],
        },
    )
    assert task.status_code == 201
    assert task.json()["resource_budget"] == dict(UNBOUNDED_RESOURCE_BUDGET)
