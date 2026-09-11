from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from vulnweaver_api import ApiSettings, create_app
from vulnweaver_api.app import (
    _artifact_download_metadata,
    _content_disposition,
    _wait_for_websocket_disconnect,
)
from vulnweaver_api.auth import SESSION_COOKIE, token_digest
from vulnweaver_contracts import (
    ArtifactVersion,
    Evidence,
    EvidenceRelation,
    EvidenceStrength,
    EvidenceType,
    FailureKind,
    Finding,
    FindingCategory,
    FindingEvidence,
    FindingStatus,
    Job,
    JobKind,
    JobStatus,
    PairFunction,
    ResourceBudget,
    Severity,
    StructuredFailure,
)
from vulnweaver_persistence import Database
from vulnweaver_persistence.models import personal_sessions


@pytest.fixture
def client(persistence_database_url: str, tmp_path: Path) -> TestClient:
    app = create_app(
        ApiSettings(
            database_url=persistence_database_url,
            artifact_store_root=tmp_path / "artifacts",
            secure_cookie=False,
            upload_max_bytes=1024 * 1024,
            max_active_sessions=2,
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


def _login_and_change_password(client: TestClient) -> str:
    login = client.post(
        "/api/auth/register",
        json={
            "schema_version": "1.0.0",
            "username": "owner",
            "password": "Changed-passphrase-456",
        },
    )
    assert login.status_code == 201
    assert login.json()["must_change_password"] is False
    assert "HttpOnly" in login.headers["set-cookie"]
    assert "SameSite=strict" in login.headers["set-cookie"]
    return login.json()["csrf_token"]


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


@pytest.mark.parametrize(
    ("report_format", "media_type", "filename"),
    [
        ("markdown", "text/markdown; charset=utf-8", "vulnweaver-report.md"),
        ("pdf", "application/pdf", "vulnweaver-report.pdf"),
        ("sarif", "application/sarif+json", "vulnweaver-report.sarif"),
    ],
)
def test_report_download_metadata_is_typed_and_named(
    report_format: str, media_type: str, filename: str
) -> None:
    version = cast(
        ArtifactVersion,
        {"generation_config": {"format": report_format}},
    )

    assert _artifact_download_metadata(version) == (media_type, filename)
    assert _content_disposition(filename).endswith(f"filename*=UTF-8''{filename}")


def test_first_registration_is_single_use_and_establishes_session(client: TestClient) -> None:
    assert client.get("/api/auth/installation").json()["registration_open"] is True
    first = client.post(
        "/api/auth/register",
        json={"schema_version": "1.0.0", "username": "owner", "password": "Long-passphrase-123"},
    )
    assert first.status_code == 201
    assert client.get("/api/auth/installation").json()["registration_open"] is False
    second = client.post(
        "/api/auth/register",
        json={"schema_version": "1.0.0", "username": "other", "password": "Other-passphrase-456"},
    )
    assert second.status_code == 409
    assert client.get("/api/auth/me").json()["username"] == "owner"


def test_concurrent_first_registration_has_exactly_one_winner(client: TestClient) -> None:
    def submit(username: str) -> int:
        response = client.post(
            "/api/auth/register",
            json={
                "schema_version": "1.0.0",
                "username": username,
                "password": "Concurrent-passphrase-123",
            },
        )
        return response.status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(submit, ("owner-a", "owner-b")))
    assert sorted(statuses) == [201, 409]


def test_product_settings_require_auth_and_never_echo_api_key(
    client: TestClient,
) -> None:
    assert client.get("/api/settings").status_code == 401
    assert client.put("/api/settings", json={"schema_version": "1.0.0"}).status_code == 401
    csrf = _login_and_change_password(client)
    saved = client.put(
        "/api/settings",
        headers={"X-CSRF-Token": csrf},
        json={
            "schema_version": "1.0.0",
            "review_model_base_url": "https://models.example/v1/",
            "review_model_name": "reviewer",
            "review_model_timeout_seconds": 45,
            "review_model_max_attempts": 3,
            "review_model_repair_attempts": 1,
            "review_model_min_interval_seconds": 0.5,
            "review_model_api_key": "must-never-be-returned",
        },
    )
    assert saved.status_code == 200
    assert saved.json()["review_model_base_url"] == "https://models.example/v1"
    assert "must-never-be-returned" not in saved.text
    assert "review_model_api_key" not in saved.json()
    assert saved.json()["api_key_configured"] is True
    assert client.get("/api/settings").json() == saved.json()
    spoofed = client.put(
        "/api/settings",
        headers={"X-CSRF-Token": csrf},
        json={**saved.json(), "review_model_api_key": None, "api_key_configured": None},
    )
    # Response-only fields are rejected, so clients cannot spoof secret state.
    assert spoofed.status_code == 422
    writable = {
        key: value
        for key, value in saved.json().items()
        if key not in {"api_key_configured", "review_model_api_key", "tier_api_keys_configured"}
    }
    preserved = client.put(
        "/api/settings",
        headers={"X-CSRF-Token": csrf},
        json={**writable, "review_model_api_key": None},
    )
    assert preserved.status_code == 200
    assert preserved.json()["api_key_configured"] is True
    cleared = client.put(
        "/api/settings",
        headers={"X-CSRF-Token": csrf},
        json={
            **writable,
            "clear_review_model_api_key": True,
        },
    )
    assert cleared.status_code == 200
    assert cleared.json()["api_key_configured"] is False


def test_product_settings_accept_and_reject_tool_image_digests(
    client: TestClient,
) -> None:
    csrf = _login_and_change_password(client)
    good = "sha256:" + "a" * 64

    saved = client.put(
        "/api/settings",
        headers={"X-CSRF-Token": csrf},
        json={
            "schema_version": "1.0.0",
            "review_model_base_url": "",
            "review_model_name": "",
            "tool_image_digests": {"binary_tools": good, "proof_tool": None, "afl_casr": None},
            "sandbox_budgets": {"afl": {"cpu_millis": 5000, "timeout_seconds": 90}},
            "fuzz_budgets": {
                "max_executions": 500,
                "max_duration_seconds": 60,
                "max_crashes": 8,
            },
            "sandbox_runner_timeout_seconds": 45,
            "fuzz_runner_timeout_seconds": 900,
            "angr_enabled": True,
        },
    )
    assert saved.status_code == 200, saved.text
    body = saved.json()
    assert body["tool_image_digests"] == {
        "binary_tools": good,
        "proof_tool": None,
        "afl_casr": None,
    }
    assert body["sandbox_budgets"]["afl"]["cpu_millis"] == 5000
    assert body["sandbox_budgets"]["afl"]["timeout_seconds"] == 90
    assert body["fuzz_budgets"]["max_executions"] == 500
    assert body["sandbox_runner_timeout_seconds"] == 45
    assert body["angr_enabled"] is True
    assert client.get("/api/settings").json() == body

    malformed = client.put(
        "/api/settings",
        headers={"X-CSRF-Token": csrf},
        json={**body, "tool_image_digests": {"binary_tools": "sha256:xyz"}},
    )
    assert malformed.status_code == 422
    out_of_range = client.put(
        "/api/settings",
        headers={"X-CSRF-Token": csrf},
        json={
            **body,
            "fuzz_budgets": {
                "max_executions": 2_000_000_000,
                "max_duration_seconds": 0,
                "max_crashes": 0,
            },
        },
    )
    assert out_of_range.status_code == 422


def test_product_settings_tier_models_and_api_key_isolation(client: TestClient) -> None:
    csrf = _login_and_change_password(client)

    saved = client.put(
        "/api/settings",
        headers={"X-CSRF-Token": csrf},
        json={
            "schema_version": "1.0.0",
            "review_model_base_url": "",
            "review_model_name": "",
            "model_tiers": {
                "planning": {
                    "protocol": "anthropic",
                    "base_url": "https://claude.example/v1/",
                    "model_name": "claude-planner",
                    "context_window_tokens": 200000,
                    "thinking_mode": "custom",
                    "thinking_budget_tokens": 8192,
                },
                "review": {
                    "protocol": "openai",
                    "base_url": "https://glm.example/v1",
                    "model_name": "glm-reviewer",
                },
            },
            "tier_api_keys": {"planning": "claude-key-never-echoed"},
        },
    )
    assert saved.status_code == 200, saved.text
    body = saved.json()
    assert "claude-key-never-echoed" not in saved.text
    assert body["model_tiers"]["planning"]["base_url"] == "https://claude.example/v1"
    assert body["model_tiers"]["planning"]["protocol"] == "anthropic"
    assert body["model_tiers"]["planning"]["thinking_budget_tokens"] == 8192
    assert body["tier_api_keys_configured"] == {
        "planning": True,
        "audit": False,
        "review": False,
        "report": False,
    }
    assert "tier_api_keys" not in body

    # a follow-up save without keys preserves the stored tier key
    preserved = client.put(
        "/api/settings",
        headers={"X-CSRF-Token": csrf},
        json={
            "schema_version": "1.0.0",
            "review_model_base_url": "",
            "review_model_name": "",
            "model_tiers": body["model_tiers"],
        },
    )
    assert preserved.status_code == 200
    assert preserved.json()["tier_api_keys_configured"]["planning"] is True
    assert "claude-key-never-echoed" not in preserved.text

    # clearing the tier key removes it without touching other tiers
    cleared = client.put(
        "/api/settings",
        headers={"X-CSRF-Token": csrf},
        json={
            "schema_version": "1.0.0",
            "review_model_base_url": "",
            "review_model_name": "",
            "model_tiers": body["model_tiers"],
            "clear_tier_api_keys": ["planning"],
        },
    )
    assert cleared.status_code == 200
    assert cleared.json()["tier_api_keys_configured"]["planning"] is False

    # custom thinking below the 1024-token floor is rejected
    invalid_budget = client.put(
        "/api/settings",
        headers={"X-CSRF-Token": csrf},
        json={
            "schema_version": "1.0.0",
            "review_model_base_url": "",
            "review_model_name": "",
            "model_tiers": {
                "planning": {
                    "protocol": "anthropic",
                    "base_url": "https://claude.example/v1",
                    "model_name": "claude-planner",
                    "thinking_mode": "custom",
                    "thinking_budget_tokens": 512,
                },
            },
        },
    )
    assert invalid_budget.status_code == 422

    # a tier with base_url but no model name (or vice versa) is rejected
    incomplete = client.put(
        "/api/settings",
        headers={"X-CSRF-Token": csrf},
        json={
            "schema_version": "1.0.0",
            "review_model_base_url": "",
            "review_model_name": "",
            "model_tiers": {"audit": {"base_url": "https://x.example/v1", "model_name": ""}},
        },
    )
    assert incomplete.status_code == 422


def test_websocket_disconnect_listener_consumes_until_disconnect() -> None:
    class FakeWebSocket:
        def __init__(self) -> None:
            self.messages = iter(
                (
                    {"type": "websocket.receive", "text": "ignored"},
                    {"type": "websocket.disconnect", "code": 1000},
                )
            )
            self.receive_count = 0

        async def receive(self) -> dict[str, object]:
            self.receive_count += 1
            return next(self.messages)

    websocket = FakeWebSocket()

    asyncio.run(_wait_for_websocket_disconnect(websocket))  # type: ignore[arg-type]

    assert websocket.receive_count == 2


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
        f"/api/projects/{project['id']}/artifacts?kind=source_archive",
        headers={
            "Content-Type": "application/octet-stream",
            "X-Artifact-Filename": "empty.zip",
            "X-CSRF-Token": csrf,
            "Idempotency-Key": "artifact:empty-key",
        },
        content=b"",
    )
    assert empty.status_code == 422
    assert empty.json()["error_code"] == "empty_artifact"

    upload = client.post(
        f"/api/projects/{project['id']}/artifacts?kind=source_archive",
        headers={
            "Content-Type": "application/octet-stream",
            "X-Artifact-Filename": "sample.zip",
            "X-CSRF-Token": csrf,
            "Idempotency-Key": "artifact:test-key",
        },
        content=b"PK\x03\x04harmless",
    )
    assert upload.status_code == 201
    artifact = upload.json()["artifact"]
    version = upload.json()["versions"][0]

    content = client.get(f"/api/artifacts/{artifact['id']}/content")
    assert content.status_code == 200
    assert content.content == b"PK\x03\x04harmless"
    assert content.headers["etag"] == f'"{version["digest"]}"'
    assert content.headers["content-disposition"] == (
        'attachment; filename="sample.zip"; filename*=UTF-8\'\'sample.zip'
    )

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
    assert task.json()["status"] == "created"
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
    assert jobs.json() == []
    assert client.get(f"/api/projects/{project['id']}/tasks").json()[0]["id"] == task_id
    assert client.get(f"/api/tasks/{task_id}").json()["id"] == task_id

    events = client.get(f"/api/tasks/{task_id}/events?after=-1")
    assert events.status_code == 200
    assert [event["sequence"] for event in events.json()] == [0]
    assert events.json()[0]["event_type"] == "task.requested"

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
    assert client.get(f"/api/tasks/{task_id}/jobs").json() == []
    assert [event["sequence"] for event in client.get(f"/api/tasks/{task_id}/events").json()] == [
        0,
        1,
    ]


def test_report_job_creation_is_idempotent_per_format(client: TestClient) -> None:
    """A repeat report request reuses the existing Job instead of erroring.

    Task aggregation auto-schedules the default markdown report on completion,
    so operator/API requests for the same format must return that Job.
    """

    csrf = _login_and_change_password(client)
    project = _create_project(client, csrf)
    upload = client.post(
        f"/api/projects/{project['id']}/artifacts?kind=source_archive",
        headers={
            "Content-Type": "application/octet-stream",
            "X-Artifact-Filename": "sample.zip",
            "X-CSRF-Token": csrf,
            "Idempotency-Key": "artifact:report-idem",
        },
        content=b"PKharmless",
    )
    assert upload.status_code == 201
    artifact = upload.json()["artifact"]
    version = upload.json()["versions"][0]
    task = client.post(
        f"/api/projects/{project['id']}/tasks",
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": "task:report-idem"},
        json={
            "schema_version": "1.0.0",
            "artifact_version_ids": [version["id"]],
            "resource_budget": _budget(),
        },
    )
    assert task.status_code == 201
    task_id = task.json()["id"]

    def _create_report(fmt: str, key: str):
        return client.post(
            f"/api/tasks/{task_id}/reports",
            headers={"X-CSRF-Token": csrf, "Idempotency-Key": key},
            json={
                "schema_version": "1.0.0",
                "artifact_id": artifact["id"],
                "version_id": version["id"],
                "format": fmt,
            },
        )

    first = _create_report("markdown", "report:markdown-1")
    assert first.status_code == 202, first.text
    repeat = _create_report("markdown", "report:markdown-2")
    assert repeat.status_code == 202, repeat.text
    assert repeat.json()["id"] == first.json()["id"]

    pdf = _create_report("pdf", "report:pdf-1")
    assert pdf.status_code == 202, pdf.text
    assert pdf.json()["id"] != first.json()["id"]

    listed = client.get(f"/api/tasks/{task_id}/jobs")
    assert listed.status_code == 200
    report_jobs = [job for job in listed.json() if job["kind"] == "report"]
    assert sorted(job["id"] for job in report_jobs) == sorted(
        [first.json()["id"], pdf.json()["id"]]
    )


def test_task_observability_summarizes_jobs_events_and_findings(client: TestClient) -> None:
    csrf = _login_and_change_password(client)
    project = _create_project(client, csrf)
    upload = client.post(
        f"/api/projects/{project['id']}/artifacts?kind=source_archive",
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": "artifact:t22-observability"},
        content=b"PK\x03\x04harmless",
    )
    version_id = upload.json()["versions"][0]["id"]
    task_id = client.post(
        f"/api/projects/{project['id']}/tasks",
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": "task:t22-observability"},
        json={
            "schema_version": "1.0.0",
            "artifact_version_ids": [version_id],
            "resource_budget": _budget(),
        },
    ).json()["id"]

    async def seed_failed_job() -> None:
        database = client.app.state.database
        assert isinstance(database, Database)
        async with database.transaction() as repositories:
            await repositories.jobs.create_without_outbox(
                Job(
                    schema_version="1.0.0",
                    id="job:t22-observability",
                    task_id=task_id,
                    kind=JobKind.SOURCE_ANALYSIS,
                    input_refs=["cas://sha256/" + "a" * 64],
                    status=JobStatus.FAILED,
                    idempotency_key="job:t22-observability",
                    resource_budget=cast(ResourceBudget, _budget()),
                    retry_policy={
                        "max_attempts": 2,
                        "backoff_seconds": 1.0,
                        "retryable_failure_kinds": [],
                    },
                    attempt=1,
                    lease=None,
                    failure=StructuredFailure(
                        code="static.tool_failed",
                        kind=FailureKind.TOOL,
                        message="tool failed",
                        retryable=False,
                        details={},
                    ),
                    created_at="2026-09-09T00:00:00Z",
                    updated_at="2026-09-09T00:00:00Z",
                )
            )

    asyncio.run(seed_failed_job())
    summary = client.get(f"/api/tasks/{task_id}/observability")
    assert summary.status_code == 200
    payload = summary.json()
    assert payload["task_id"] == task_id
    assert payload["jobs_total"] == 1
    assert payload["jobs_by_status"] == {"failed": 1}
    assert payload["failures_by_code"] == {"static.tool_failed": 1}
    assert payload["events_total"] == 1
    assert payload["findings_total"] == 0
    assert payload["findings_by_status"] == {}


def test_finding_evidence_review_and_annotation_api_are_auditable(
    client: TestClient,
) -> None:
    csrf = _login_and_change_password(client)
    project = _create_project(client, csrf)
    upload = client.post(
        f"/api/projects/{project['id']}/artifacts?kind=source_archive",
        headers={
            "X-CSRF-Token": csrf,
            "Idempotency-Key": "artifact:t15-api",
        },
        content=b"PK\x03\x04harmless",
    )
    version_id = upload.json()["versions"][0]["id"]
    created_task = client.post(
        f"/api/projects/{project['id']}/tasks",
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": "task:t15-api"},
        json={
            "schema_version": "1.0.0",
            "artifact_version_ids": [version_id],
            "resource_budget": _budget(),
        },
    ).json()
    task_id = created_task["id"]
    finding_id = "finding:t15-api"
    evidence_id = "evidence:t15-api"
    function_id = "pair-function:t15-api"
    binary_function_id = "pair-function:t17-api"

    async def seed() -> None:
        database = client.app.state.database
        assert isinstance(database, Database)
        async with database.transaction() as repositories:
            evidence = Evidence(
                schema_version="1.0.0",
                id=evidence_id,
                type=EvidenceType.TOOL_OUTPUT,
                strength=EvidenceStrength.SUPPORTING,
                artifact_ref="cas://sha256/" + "a" * 64,
                digest="sha256:" + "a" * 64,
                tool=None,
                input_ref="cas://sha256/" + "e" * 64,
                command_hash=None,
                exit_code=0,
                stdout_ref=None,
                stderr_ref=None,
                replay_recipe={"kind": "safe-test", "reproducible": False},
                created_at="2026-09-09T00:00:00Z",
            )
            finding = Finding(
                schema_version="1.0.0",
                id=finding_id,
                task_id=task_id,
                category=FindingCategory.STATIC_ONLY,
                cwe_id="CWE-20",
                title="candidate",
                severity=Severity.MEDIUM,
                confidence=0.5,
                location={
                    "artifact_version_id": version_id,
                    "path": "src/app.py",
                    "start_line": 1,
                    "start_column": 1,
                    "end_line": 1,
                    "end_column": 2,
                },
                dataflow=[],
                call_path=[],
                status=FindingStatus.CANDIDATE,
                evidence_ids=[],
                review_ids=[],
                poc_ids=[],
                fix_suggestion="validate input",
                created_at="2026-09-09T00:00:00Z",
            )
            relation = FindingEvidence(
                schema_version="1.0.0",
                finding_id=finding_id,
                evidence_id=evidence_id,
                relation=EvidenceRelation.SUPPORTS,
                weight=0.5,
                created_by="tool:test",
                created_at="2026-09-09T00:00:00Z",
            )
            await repositories.evidence.create(evidence)
            await repositories.findings.create(finding)
            await repositories.findings.link_evidence(relation)
            await repositories.pair.import_graph(
                [
                    PairFunction(
                        schema_version="1.0.0",
                        id=function_id,
                        artifact_version_id=version_id,
                        name="main",
                        symbol="main",
                        language="python",
                        source_location={
                            "artifact_version_id": version_id,
                            "path": "src/app.py",
                            "start_line": 1,
                            "start_column": 1,
                            "end_line": 1,
                            "end_column": 2,
                        },
                        binary_location=None,
                        signature="main()",
                        attributes={},
                    ),
                    PairFunction(
                        schema_version="1.0.0",
                        id=binary_function_id,
                        artifact_version_id=version_id,
                        name="z_binary_main",
                        symbol="z_binary_main",
                        language="x86_64",
                        source_location=None,
                        binary_location={
                            "artifact_version_id": version_id,
                            "image_base": 0x400000,
                            "virtual_address": 0x401000,
                            "file_offset": None,
                            "instruction_end": 0x401010,
                        },
                        signature=None,
                        attributes={},
                    ),
                ],
                [],
                [],
                None,
                created_at=datetime(2026, 9, 9, tzinfo=UTC),
            )

    asyncio.run(seed())
    assert client.get(f"/api/tasks/{task_id}/findings").json()[0]["id"] == finding_id
    evidence = client.get(f"/api/findings/{finding_id}/evidence").json()
    assert evidence[0]["relation"]["relation"] == "supports"
    assert client.get(f"/api/tasks/{task_id}/agent-runs").json() == []
    assert client.get(f"/api/tasks/{task_id}/pair").json()[0]["id"] == function_id
    located = client.get(f"/api/tasks/{task_id}/pair/address/{0x401004}")
    assert located.status_code == 200
    assert [item["id"] for item in located.json()] == [binary_function_id]
    invalid_address = client.get(f"/api/tasks/{task_id}/pair/address/-1")
    assert invalid_address.status_code == 422
    assert invalid_address.json()["error_code"] == "invalid_binary_address"

    annotation_headers = {
        "X-CSRF-Token": csrf,
        "Idempotency-Key": "annotation:t15-api",
    }
    annotation_body = {
        "schema_version": "1.0.0",
        "target_kind": "finding",
        "target_id": finding_id,
        "labels": ["needs-review", "needs-review"],
        "note": "manual triage",
        "severity_override": "high",
        "supersedes_annotation_id": None,
    }
    annotation = client.post(
        f"/api/tasks/{task_id}/annotations",
        headers=annotation_headers,
        json=annotation_body,
    )
    assert annotation.status_code == 201
    assert annotation.json()["labels"] == ["needs-review"]
    replay = client.post(
        f"/api/tasks/{task_id}/annotations",
        headers=annotation_headers,
        json=annotation_body,
    )
    assert replay.json()["id"] == annotation.json()["id"]
    assert client.get(f"/api/tasks/{task_id}/annotations").json() == [annotation.json()]

    function_annotation = client.post(
        f"/api/tasks/{task_id}/annotations",
        headers={
            "X-CSRF-Token": csrf,
            "Idempotency-Key": "annotation:t15-function",
        },
        json={
            **annotation_body,
            "target_kind": "function",
            "target_id": function_id,
            "labels": ["entrypoint"],
            "severity_override": None,
        },
    )
    assert function_annotation.status_code == 201
    assert function_annotation.json()["target_kind"] == "function"

    review = client.patch(
        f"/api/findings/{finding_id}/review",
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": "review:t15-api"},
        json={
            "schema_version": "1.0.0",
            "outcome": "disputed",
            "rationale": "manual evidence is inconclusive",
            "supersedes_review_id": None,
        },
    )
    assert review.status_code == 201
    assert review.json()["outcome"] == "disputed"
    history = client.get(f"/api/findings/{finding_id}/reviews")
    assert history.status_code == 200
    assert [item["id"] for item in history.json()] == [review.json()["id"]]


def test_openapi_lists_control_plane_and_cookie_auth(client: TestClient) -> None:
    document = client.get("/openapi.json")
    assert document.status_code == 200
    paths = document.json()["paths"]
    assert "/api/auth/login" in paths
    assert "/api/projects/{project_id}/artifacts" in paths
    assert "/api/projects/{project_id}/tasks" in paths
    assert "/api/tasks/{task_id}/events" in paths
    assert "/api/jobs/{job_id}/retry" in paths
    login_schema = document.json()["components"]["schemas"]["LoginRequest"]
    assert login_schema["additionalProperties"] is False
    assert login_schema["properties"]["schema_version"]["const"] == "1.0.0"
    project_security = paths["/api/projects"]["get"]["security"]
    assert project_security == [{"APIKeyCookie": []}]
    upload_body = paths["/api/projects/{project_id}/artifacts"]["post"]["requestBody"]
    assert "application/octet-stream" in upload_body["content"]


def test_request_limits_and_framework_errors_are_structured(client: TestClient) -> None:
    oversized = client.post(
        "/api/auth/login",
        headers={"Content-Type": "application/json", "X-Correlation-ID": "request:large"},
        content=b'"' + b"x" * (1024 * 1024) + b'"',
    )
    assert oversized.status_code == 413
    assert oversized.json()["error_code"] == "request_body_too_large"
    assert oversized.json()["correlation_id"] == "request:large"

    missing_version = client.post(
        "/api/auth/login",
        json={"username": "owner", "password": "Initial-passphrase-123"},
    )
    assert missing_version.status_code == 422
    assert missing_version.json()["error_code"] == "request_validation_failed"

    missing = client.get("/api/not-a-route")
    assert missing.status_code == 404
    assert missing.json()["schema_version"] == "1.0.0"
    assert missing.json()["error_code"] == "http_error"


def test_authentication_errors_logout_and_correlation(client: TestClient) -> None:
    anonymous = client.get("/api/projects", headers={"X-Correlation-ID": "request:browser-1"})
    assert anonymous.status_code == 401
    assert anonymous.headers["x-correlation-id"] == "request:browser-1"
    assert anonymous.json()["correlation_id"] == "request:browser-1"

    invalid = client.post(
        "/api/auth/login",
        json={
            "schema_version": "1.0.0",
            "username": "owner",
            "password": "wrong-password",
        },
    )
    assert invalid.status_code == 401
    csrf = _login_and_change_password(client)

    me = client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["username"] == "owner"
    wrong_current = client.post(
        "/api/auth/password",
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": "password:wrong-current"},
        json={
            "schema_version": "1.0.0",
            "current_password": "not-current-password",
            "new_password": "Another-passphrase-789",
        },
    )
    assert wrong_current.status_code == 401
    weak = client.post(
        "/api/auth/password",
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": "password:weak-value"},
        json={
            "schema_version": "1.0.0",
            "current_password": "Changed-passphrase-456",
            "new_password": "too-short",
        },
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

    multipart = client.post(
        f"/api/projects/{project['id']}/artifacts?kind=pe",
        headers={
            "Content-Type": "multipart/form-data; boundary=legacy",
            "X-CSRF-Token": csrf,
            "Idempotency-Key": "artifact:legacy-multipart",
        },
        content=b"--legacy--",
    )
    assert multipart.status_code == 415
    assert multipart.json()["error_code"] == "http_error"

    derived = client.post(
        f"/api/projects/{project['id']}/artifacts?kind=derived",
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": "artifact:derived"},
        content=b"MZpayload",
    )
    assert derived.status_code == 422
    mismatch = client.post(
        f"/api/projects/{project['id']}/artifacts?kind=elf",
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": "artifact:mismatch"},
        content=b"MZpayload",
    )
    assert mismatch.status_code == 422
    too_large = client.post(
        f"/api/projects/{project['id']}/artifacts?kind=source_archive",
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": "artifact:large"},
        content=b"PK\x03\x04" + b"x" * (1024 * 1024),
    )
    assert too_large.status_code == 413

    upload_headers = {"X-CSRF-Token": csrf, "Idempotency-Key": "artifact:query-key"}
    upload = client.post(
        f"/api/projects/{project['id']}/artifacts?kind=pe",
        headers=upload_headers,
        content=b"MZharmless",
    )
    assert upload.status_code == 201
    artifact_id = upload.json()["artifact"]["id"]
    replay = client.post(
        f"/api/projects/{project['id']}/artifacts?kind=pe",
        headers=upload_headers,
        content=b"MZharmless",
    )
    assert replay.json()["artifact"]["id"] == artifact_id
    conflict = client.post(
        f"/api/projects/{project['id']}/artifacts?kind=pe",
        headers=upload_headers,
        content=b"MZdifferent",
    )
    assert conflict.status_code == 409
    stored_objects = list(
        (client.app.state.settings.artifact_store_root / "objects" / "sha256").glob("*/*")
    )
    assert len(stored_objects) == 1
    assert client.get(f"/api/projects/{project['id']}/artifacts").json()[0]["id"] == artifact_id
    assert client.get(f"/api/projects/{project['id']}/artifacts/{artifact_id}").status_code == 200
    second_project = _create_project(
        client, csrf, key="project:artifact-owner", name="Other project"
    )
    wrong_project = client.get(f"/api/projects/{second_project['id']}/artifacts/{artifact_id}")
    assert wrong_project.status_code == 422

    elf = client.post(
        f"/api/projects/{project['id']}/artifacts?kind=elf",
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": "artifact:elf-key"},
        content=b"\x7fELFharmless",
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
    monkeypatch.setenv("UPLOAD_MAX_BYTES", "4096")
    monkeypatch.setenv("SESSION_TTL_SECONDS", "600")
    monkeypatch.setenv("SECURE_COOKIE", "false")
    settings = ApiSettings.from_env()
    assert settings.upload_max_bytes == 4096
    assert settings.session_ttl_seconds == 600
    assert settings.secure_cookie is False

    with pytest.raises(ValueError, match="upload"):
        ApiSettings(settings.database_url, tmp_path, upload_max_bytes=0)
    with pytest.raises(ValueError, match="session"):
        ApiSettings(settings.database_url, tmp_path, session_ttl_seconds=60)


def test_repeated_login_failures_lock_personal_account(client: TestClient) -> None:
    _login_and_change_password(client)
    for _ in range(5):
        response = client.post(
            "/api/auth/login",
            json={
                "schema_version": "1.0.0",
                "username": "owner",
                "password": "wrong-password",
            },
        )
        assert response.status_code == 401
    locked = client.post(
        "/api/auth/login",
        json={
            "schema_version": "1.0.0",
            "username": "owner",
            "password": "Changed-passphrase-456",
        },
    )
    assert locked.status_code == 401
    assert locked.json()["message"] == "invalid username or password"


def test_active_sessions_are_bounded(client: TestClient, persistence_database_url: str) -> None:
    _login_and_change_password(client)
    oldest_token = client.cookies[SESSION_COOKIE]
    for _ in range(2):
        login = client.post(
            "/api/auth/login",
            json={
                "schema_version": "1.0.0",
                "username": "owner",
                "password": "Changed-passphrase-456",
            },
        )
        assert login.status_code == 200

    engine = create_engine(persistence_database_url)
    try:
        with engine.connect() as connection:
            count = connection.scalar(select(func.count()).select_from(personal_sessions))
            oldest = connection.scalar(
                select(personal_sessions.c.token_digest).where(
                    personal_sessions.c.token_digest == token_digest(oldest_token)
                )
            )
        assert count == 2
        assert oldest is None
    finally:
        engine.dispose()


def test_restart_uses_persisted_registered_account(client: TestClient) -> None:
    _login_and_change_password(client)
    settings = client.app.state.settings
    restarted = create_app(settings)
    with TestClient(restarted) as restarted_client:
        login = restarted_client.post(
            "/api/auth/login",
            json={
                "schema_version": "1.0.0",
                "username": "owner",
                "password": "Changed-passphrase-456",
            },
        )
        assert login.status_code == 200


def test_failed_job_retry_requeues_publishes_event_and_conflicts(
    client: TestClient, persistence_database_url: str
) -> None:
    csrf = _login_and_change_password(client)
    project = _create_project(client, csrf)
    upload = client.post(
        f"/api/projects/{project['id']}/artifacts?kind=source_archive",
        headers={
            "Content-Type": "application/octet-stream",
            "X-Artifact-Filename": "sample.zip",
            "X-CSRF-Token": csrf,
            "Idempotency-Key": "artifact:retry",
        },
        content=b"PKharmless",
    )
    assert upload.status_code == 201
    artifact = upload.json()["artifact"]
    version = upload.json()["versions"][0]
    task = client.post(
        f"/api/projects/{project['id']}/tasks",
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": "task:retry"},
        json={
            "schema_version": "1.0.0",
            "artifact_version_ids": [version["id"]],
            "resource_budget": _budget(),
        },
    )
    assert task.status_code == 201
    task_id = task.json()["id"]
    report = client.post(
        f"/api/tasks/{task_id}/reports",
        headers={"X-CSRF-Token": csrf, "Idempotency-Key": "report:retry"},
        json={
            "schema_version": "1.0.0",
            "artifact_id": artifact["id"],
            "version_id": version["id"],
            "format": "markdown",
        },
    )
    assert report.status_code == 202
    job_id = report.json()["id"]

    failure = (
        '{"code": "model.timeout", "kind": "timeout", '
        '"message": "upstream timed out", "retryable": false}'
    )
    engine = create_engine(persistence_database_url)
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(
                "UPDATE jobs SET status = 'failed', failure = "
                f"'{failure}'::jsonb, updated_at = now() WHERE id = '{job_id}'"
            )
    finally:
        engine.dispose()

    unauthenticated = client.post(f"/api/jobs/{job_id}/retry")
    assert unauthenticated.status_code == 401

    retried = client.post(f"/api/jobs/{job_id}/retry", headers={"X-CSRF-Token": csrf})
    assert retried.status_code == 200, retried.text
    body = retried.json()
    assert body["id"] == job_id
    assert body["status"] == "queued"
    assert body["attempt"] == 0
    assert body["failure"] is None
    assert body["lease"] is None

    engine = create_engine(persistence_database_url)
    try:
        with engine.begin() as connection:
            row = connection.exec_driver_sql(
                "SELECT event_type, sequence, published_at FROM outbox_events "
                f"WHERE aggregate_type = 'job' AND aggregate_id = '{job_id}' "
                "ORDER BY sequence DESC LIMIT 1"
            ).one()
            assert row[0] == "job.requested"
            assert row[1] >= 1
            assert row[2] is None
    finally:
        engine.dispose()

    conflict = client.post(f"/api/jobs/{job_id}/retry", headers={"X-CSRF-Token": csrf})
    assert conflict.status_code == 409
    assert conflict.json()["error_code"] == "entity_conflict"

    missing = client.post("/api/jobs/job:does-not-exist/retry", headers={"X-CSRF-Token": csrf})
    assert missing.status_code == 404
    assert missing.json()["error_code"] == "entity_not_found"
