"""A project budget must cover the ToolSpecs the deployment actually ships.

The Policy Engine refuses an initial analysis step whose ToolSpec limits exceed the project
budget, so a default below the shipped specs makes every task fail with no visible reason.
These tests pin the two sides together by loading the real ``deploy/tool-specs`` directory.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from vulnweaver_api import ApiSettings, create_app
from vulnweaver_api.budgets import (
    MINIMUM_DYNAMIC_RUNS,
    RESOURCE_BUDGET_KEYS,
    minimum_resource_budget,
    resolve_project_budget,
)
from vulnweaver_api.errors import ApiInputError
from vulnweaver_contracts import ResourceBudget
from vulnweaver_tool_runtime import ToolSpecLoader

SHIPPED_TOOL_SPECS = Path(__file__).resolve().parents[2] / "deploy" / "tool-specs"


@pytest.fixture(scope="module")
def shipped_registry() -> ToolSpecLoader:
    return ToolSpecLoader.load_directory(SHIPPED_TOOL_SPECS)


def test_shipped_tool_specs_are_loadable(shipped_registry: ToolSpecLoader) -> None:
    assert len(shipped_registry.snapshot()) > 0


def test_omitted_budget_defaults_to_the_shipped_floor(
    shipped_registry: ToolSpecLoader,
) -> None:
    resolved = resolve_project_budget(
        shipped_registry, None, exploit_validation_enabled=False
    )
    floor = minimum_resource_budget(shipped_registry)
    assert floor is not None
    for key in RESOURCE_BUDGET_KEYS:
        assert resolved[key] >= floor[key]
    # Dynamic execution is a first-class capability, so the default must leave runs available.
    assert resolved["max_dynamic_runs"] >= MINIMUM_DYNAMIC_RUNS


def test_budget_below_the_shipped_floor_is_rejected(
    shipped_registry: ToolSpecLoader,
) -> None:
    floor = minimum_resource_budget(shipped_registry)
    assert floor is not None
    undersized = ResourceBudget(**{**floor, "cpu_millis": floor["cpu_millis"] - 1})
    with pytest.raises(ApiInputError) as caught:
        resolve_project_budget(
            shipped_registry, undersized, exploit_validation_enabled=False
        )
    assert caught.value.code == "resource_budget_below_tool_requirements"
    assert "cpu_millis" in caught.value.message


def test_budget_at_the_shipped_floor_is_accepted(
    shipped_registry: ToolSpecLoader,
) -> None:
    floor = minimum_resource_budget(shipped_registry)
    assert floor is not None
    resolved = resolve_project_budget(
        shipped_registry, floor, exploit_validation_enabled=False
    )
    assert resolved == floor


def test_exploit_validation_requires_a_dynamic_run(
    shipped_registry: ToolSpecLoader,
) -> None:
    floor = minimum_resource_budget(shipped_registry)
    assert floor is not None
    blocked = ResourceBudget(**{**floor, "max_dynamic_runs": 0})
    with pytest.raises(ApiInputError) as caught:
        resolve_project_budget(
            shipped_registry, blocked, exploit_validation_enabled=True
        )
    assert caught.value.code == "resource_budget_blocks_dynamic_runs"
    # The same budget is acceptable when the project does not enable exploit validation.
    assert (
        resolve_project_budget(
            shipped_registry, blocked, exploit_validation_enabled=False
        )["max_dynamic_runs"]
        == 0
    )


def test_missing_tool_spec_directory_requires_an_explicit_budget() -> None:
    with pytest.raises(ApiInputError) as caught:
        resolve_project_budget(None, None, exploit_validation_enabled=False)
    assert caught.value.code == "resource_budget_required"


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


def test_project_without_a_budget_gets_one_that_covers_every_shipped_tool(
    spec_aware_client: TestClient, shipped_registry: ToolSpecLoader
) -> None:
    csrf = _register(spec_aware_client)
    response = _create_project(spec_aware_client, csrf, None)
    assert response.status_code == 201

    floor = minimum_resource_budget(shipped_registry)
    assert floor is not None
    stored = response.json()["resource_budget"]
    for key in RESOURCE_BUDGET_KEYS:
        assert stored[key] >= floor[key]


def test_project_with_a_budget_below_the_shipped_tools_is_rejected(
    spec_aware_client: TestClient, shipped_registry: ToolSpecLoader
) -> None:
    floor = minimum_resource_budget(shipped_registry)
    assert floor is not None
    csrf = _register(spec_aware_client)
    response = _create_project(
        spec_aware_client, csrf, {**floor, "cpu_millis": floor["cpu_millis"] - 1}
    )
    assert response.status_code == 422
    assert response.json()["error_code"] == "resource_budget_below_tool_requirements"
    assert "cpu_millis" in response.json()["message"]
