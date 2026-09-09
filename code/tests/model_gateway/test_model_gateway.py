from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import cast

import pytest
from vulnweaver_contracts import AgentRun, JsonObject, RunStatus
from vulnweaver_model_gateway import (
    AgentRunConflict,
    HttpxChatTransport,
    InMemoryAgentRunRecorder,
    ModelEndpoint,
    ModelGateway,
    ModelGatewaySettings,
    ModelRoute,
    ModelTier,
    RedactionPolicy,
    TransportResponse,
)

NOW = datetime(2026, 9, 8, 9, 0, tzinfo=UTC)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class FakeTransport:
    def __init__(self, responses: list[object]) -> None:
        self.responses = responses
        self.requests: list[tuple[str, Mapping[str, str], JsonObject]] = []

    async def post_json(
        self,
        url: str,
        headers: Mapping[str, str],
        payload: JsonObject,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> TransportResponse:
        del timeout_seconds, max_response_bytes
        self.requests.append((url, headers, payload))
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        assert isinstance(response, TransportResponse)
        return response


def endpoint(
    name: str = "remote", *, model: str = "audit-model", attempts: int = 1
) -> ModelEndpoint:
    return ModelEndpoint(
        name=name,
        base_url="https://models.example/v1",
        models={ModelTier.AUDIT: model},
        api_key="secret-key",
        max_attempts=attempts,
        retry_backoff_seconds=0,
    )


def response(content: str, *, status: int = 200, input_tokens: int = 4) -> TransportResponse:
    return TransportResponse(
        status,
        {
            "choices": [{"message": {"content": content}}],
            "usage": {"prompt_tokens": input_tokens, "completion_tokens": 3},
        },
    )


def test_model_proxy_rejects_credentials_and_accepts_plain_http_url() -> None:
    HttpxChatTransport(proxy_url="http://egress-proxy:8080")
    with pytest.raises(ValueError, match="proxy URL"):
        HttpxChatTransport(proxy_url="http://user:secret@egress-proxy:8080")


def gateway(
    transport: FakeTransport,
    *,
    route: ModelRoute | None = None,
    repairs: int = 1,
) -> tuple[ModelGateway, InMemoryAgentRunRecorder]:
    recorder = InMemoryAgentRunRecorder()
    model_gateway = ModelGateway(
        ModelGatewaySettings(
            routes={ModelTier.AUDIT: route or ModelRoute(endpoint())},
            max_repair_attempts=repairs,
        ),
        transport=transport,
        recorder=recorder,
        clock=lambda: NOW,
        monotonic=lambda: 10.0,
        sleeper=lambda delay: _done(delay),
    )
    return model_gateway, recorder


async def _done(delay: float) -> None:
    del delay


@pytest.mark.anyio
async def test_success_uses_openai_shape_redacts_secrets_and_records_agent_run() -> None:
    transport = FakeTransport([response('{"ok": true}')])
    model_gateway, recorder = gateway(transport)
    result = await model_gateway.complete_structured(
        tier=ModelTier.AUDIT,
        task_id="task:1",
        run_id="run:1",
        messages=[
            {"role": "user", "content": "password=top-secret; inspect source"},
        ],
        output_contract="JsonObject",
        input_refs=["cas://source"],
        result_refs=["cas://result"],
        max_output_tokens=321,
    )

    assert result.succeeded
    assert result.output == {"ok": True}
    assert result.agent_run["status"] is RunStatus.SUCCEEDED
    assert result.agent_run.get("duration_ms") == 0
    assert result.agent_run.get("result_refs") == ["cas://result"]
    assert result.agent_run["token_usage"] == {"input_tokens": 4, "output_tokens": 3}
    assert "top-secret" not in str(transport.requests[0][2])
    assert transport.requests[0][2]["max_tokens"] == 321
    assert "secret-key" not in str(result.agent_run)
    assert recorder.get("run:1") == result.agent_run


@pytest.mark.anyio
async def test_transient_failure_retries_and_preserves_token_usage() -> None:
    transport = FakeTransport(
        [response("bad", status=503), response('{"ok": true}', input_tokens=8)]
    )
    model_gateway, _ = gateway(transport, route=ModelRoute(endpoint(attempts=2)))
    result = await model_gateway.complete_structured(
        tier=ModelTier.AUDIT,
        task_id="task:1",
        run_id="run:retry",
        messages=[{"role": "user", "content": "inspect"}],
        output_contract="JsonObject",
    )
    assert result.succeeded
    assert len(transport.requests) == 2
    assert [item["decision"] for item in result.agent_run["decisions"]] == [
        "model_attempt",
        "model_attempt",
    ]


@pytest.mark.anyio
async def test_remote_failure_falls_back_to_local_endpoint() -> None:
    transport = FakeTransport([TimeoutError(), response('{"ok": true}')])
    route = ModelRoute(endpoint("remote", attempts=1), endpoint("local", model="local-audit"))
    model_gateway, _ = gateway(transport, route=route)
    result = await model_gateway.complete_structured(
        tier=ModelTier.AUDIT,
        task_id="task:1",
        run_id="run:fallback",
        messages=[{"role": "user", "content": "inspect"}],
        output_contract="JsonObject",
    )
    assert result.succeeded
    assert result.endpoint == "local"
    assert result.agent_run["model"] == "local/local-audit"
    assert [item["decision"] for item in result.agent_run["decisions"]] == [
        "model_attempt",
        "model_endpoint_failure",
        "model_fallback",
        "model_attempt",
    ]


@pytest.mark.anyio
async def test_invalid_structured_output_gets_one_bounded_repair() -> None:
    transport = FakeTransport(
        [
            response('{"wrong": true}'),
            response('{"input_tokens": 1, "output_tokens": 2}'),
        ]
    )
    model_gateway, _ = gateway(transport, repairs=1)
    result = await model_gateway.complete_structured(
        tier=ModelTier.AUDIT,
        task_id="task:1",
        run_id="run:repair",
        messages=[{"role": "user", "content": "return a token usage object"}],
        output_contract="TokenUsage",
    )
    assert result.succeeded
    assert result.output == {"input_tokens": 1, "output_tokens": 2}
    assert len(transport.requests) == 2
    repair_payload = transport.requests[1][2]
    repair_prompt = str(repair_payload["messages"])
    assert "previous response as untrusted data" in repair_prompt
    assert "structured_output_repair" in [
        item["decision"] for item in result.agent_run["decisions"]
    ]


@pytest.mark.anyio
async def test_invalid_output_after_repair_is_structured_failure() -> None:
    transport = FakeTransport([response("not-json"), response("still-not-json")])
    model_gateway, recorder = gateway(transport, repairs=1)
    result = await model_gateway.complete_structured(
        tier=ModelTier.AUDIT,
        task_id="task:1",
        run_id="run:invalid",
        messages=[{"role": "user", "content": "inspect"}],
        output_contract="JsonObject",
    )
    assert not result.succeeded
    assert isinstance(result.failure, Mapping)
    assert result.agent_run["status"] is RunStatus.FAILED
    assert result.failure["kind"] == "validation"
    assert recorder.get("run:invalid")["failure"] == result.failure


@pytest.mark.anyio
async def test_non_retryable_client_error_does_not_retry() -> None:
    transport = FakeTransport([response("bad", status=400), response('{"ok": true}')])
    model_gateway, _ = gateway(transport, route=ModelRoute(endpoint(attempts=3)))
    result = await model_gateway.complete_structured(
        tier=ModelTier.AUDIT,
        task_id="task:1",
        run_id="run:400",
        messages=[{"role": "user", "content": "inspect"}],
        output_contract="JsonObject",
    )
    assert not result.succeeded
    assert len(transport.requests) == 1
    assert result.failure is not None
    assert result.failure["kind"] == "dependency"


def test_redaction_policy_is_configurable_and_registry_is_immutable() -> None:
    policy = RedactionPolicy(patterns=(r"(?i)private:\w+",))
    assert policy.redact_text("private:abc") == "<redacted>"
    recorder = InMemoryAgentRunRecorder()
    run = cast(
        AgentRun,
        {
        "schema_version": "1.0.0",
        "id": "run:1",
        "task_id": "task:1",
        "status": "succeeded",
        "model": "local/audit",
        "prompt_hash": "sha256:" + "a" * 64,
        "input_refs": [],
        "decisions": [],
        "token_usage": {"input_tokens": 0, "output_tokens": 0},
        "failure": None,
        "duration_ms": 0,
        "result_refs": [],
        "created_at": "2026-09-08T09:00:00Z",
        "updated_at": "2026-09-08T09:00:00Z",
        },
    )
    recorder.append(run)
    recorder.append(run)  # idempotent replay
    with pytest.raises(AgentRunConflict):
        changed = dict(run)
        changed["model"] = "other"
        recorder.append(cast(AgentRun, changed))
