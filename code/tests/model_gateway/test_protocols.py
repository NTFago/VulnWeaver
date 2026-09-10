"""Protocol-level tests: Anthropic wire format, thinking modes, context budget."""

from __future__ import annotations

from typing import cast

import pytest
from vulnweaver_contracts import JsonObject
from vulnweaver_model_gateway import (
    HttpxChatTransport,
    ModelEndpoint,
    ModelGateway,
    ModelGatewaySettings,
    ModelRoute,
    ModelTier,
    ThinkingConfig,
    TransportResponse,
)
from vulnweaver_model_gateway.gateway import _reasoning_effort

from tests.model_gateway.test_model_gateway import FakeTransport


def anthropic_endpoint(**overrides: object) -> ModelEndpoint:
    values: dict[str, object] = {
        "name": "claude",
        "base_url": "https://api.anthropic.example/v1",
        "models": {ModelTier.AUDIT: "claude-probe"},
        "api_key": "anthropic-secret",
        "max_attempts": 1,
        "retry_backoff_seconds": 0.0,
        "protocol": "anthropic",
    }
    values.update(overrides)
    return ModelEndpoint(**values)  # type: ignore[arg-type]


def anthropic_response(
    text: str, *, input_tokens: int = 7, output_tokens: int = 11
) -> TransportResponse:
    return TransportResponse(
        200,
        {
            "content": [
                {"type": "thinking", "thinking": "internal reasoning"},
                {"type": "text", "text": text},
            ],
            "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens},
        },
    )


@pytest.mark.anyio
async def test_anthropic_request_uses_messages_wire_format() -> None:
    transport = FakeTransport([anthropic_response('{"ok": true}')])
    gateway = ModelGateway(
        ModelGatewaySettings(
            routes={ModelTier.AUDIT: ModelRoute(anthropic_endpoint())},
            max_repair_attempts=0,
        ),
        transport=transport,
    )
    result = await gateway.complete_structured(
        tier=ModelTier.AUDIT,
        task_id="task:anthropic",
        run_id="run:anthropic",
        messages=[
            {"role": "system", "content": "You audit code."},
            {"role": "user", "content": "Return JSON."},
        ],
        output_contract="JsonObject",
    )
    assert result.succeeded
    url, headers, payload = transport.requests[0]
    assert url == "https://api.anthropic.example/v1/messages"
    assert headers["x-api-key"] == "anthropic-secret"
    assert headers["anthropic-version"] == "2023-06-01"
    assert "Authorization" not in headers
    assert payload["model"] == "claude-probe"
    assert payload["system"] == "You audit code."
    # The JSON directive rides on the final user turn for Anthropic.
    messages = cast(list[dict[str, str]], payload["messages"])
    assert messages[-1]["content"].startswith("Return JSON.")
    assert "single JSON object" in messages[-1]["content"]
    assert payload["max_tokens"] == 4096  # default reserve without a context window
    # usage maps from Anthropic's vocabulary into the recorded AgentRun
    token_usage = result.agent_run["token_usage"]
    assert isinstance(token_usage, dict)
    assert token_usage["input_tokens"] == 7
    assert token_usage["output_tokens"] == 11


@pytest.mark.anyio
async def test_anthropic_thinking_budget_reaches_payload() -> None:
    transport = FakeTransport([anthropic_response('{"ok": true}')])
    gateway = ModelGateway(
        ModelGatewaySettings(
            routes={
                ModelTier.AUDIT: ModelRoute(
                    anthropic_endpoint(
                        thinking=ThinkingConfig(mode="custom", budget_tokens=4096),
                        context_window_tokens=100_000,
                    )
                )
            },
            max_repair_attempts=0,
        ),
        transport=transport,
    )
    result = await gateway.complete_structured(
        tier=ModelTier.AUDIT,
        task_id="task:thinking",
        run_id="run:thinking",
        messages=[{"role": "user", "content": "Return JSON."}],
        output_contract="JsonObject",
    )
    assert result.succeeded
    payload = cast(JsonObject, transport.requests[0][2])
    assert payload["thinking"] == {"type": "enabled", "budget_tokens": 4096}


def test_openai_reasoning_effort_mapping() -> None:
    low = ModelEndpoint(
        name="m",
        base_url="https://models.example/v1",
        models={ModelTier.REVIEW: "r"},
        thinking=ThinkingConfig(mode="custom", budget_tokens=2048),
    )
    medium = ModelEndpoint(
        name="m",
        base_url="https://models.example/v1",
        models={ModelTier.REVIEW: "r"},
        thinking=ThinkingConfig(mode="default"),
    )
    high = ModelEndpoint(
        name="m",
        base_url="https://models.example/v1",
        models={ModelTier.REVIEW: "r"},
        thinking=ThinkingConfig(mode="custom", budget_tokens=32000),
    )
    off = ModelEndpoint(
        name="m",
        base_url="https://models.example/v1",
        models={ModelTier.REVIEW: "r"},
    )
    assert _reasoning_effort(low) == "low"
    assert _reasoning_effort(medium) == "medium"
    assert _reasoning_effort(high) == "high"
    assert _reasoning_effort(off) is None


def test_thinking_config_rejects_invalid_modes_and_budgets() -> None:
    with pytest.raises(ValueError, match="thinking mode"):
        ThinkingConfig(mode="yolo")
    with pytest.raises(ValueError, match="at least 1024"):
        ThinkingConfig(mode="custom", budget_tokens=512)
    with pytest.raises(ValueError, match="context window"):
        ModelEndpoint(
            name="m",
            base_url="https://models.example/v1",
            models={ModelTier.REVIEW: "r"},
            context_window_tokens=4096,
            thinking=ThinkingConfig(mode="custom", budget_tokens=8192),
        )


def test_unknown_protocol_rejected() -> None:
    with pytest.raises(ValueError, match="protocol"):
        ModelEndpoint(
            name="m",
            base_url="https://models.example/v1",
            models={ModelTier.REVIEW: "r"},
            protocol="gemini",
        )


@pytest.mark.anyio
async def test_context_window_guard_rejects_oversized_input() -> None:
    transport = FakeTransport([])
    gateway = ModelGateway(
        ModelGatewaySettings(
            routes={
                ModelTier.AUDIT: ModelRoute(
                    anthropic_endpoint(
                        context_window_tokens=200
                    )
                )
            },
            max_repair_attempts=0,
        ),
        transport=transport,
    )
    result = await gateway.complete_structured(
        tier=ModelTier.AUDIT,
        task_id="task:window",
        run_id="run:window",
        messages=[{"role": "user", "content": "x" * 2000}],
        output_contract="JsonObject",
    )
    assert not result.succeeded
    assert result.failure is not None
    assert "context window" in str(result.failure["message"])
    assert transport.requests == []


def test_anthropic_messages_url_appends_to_v1_root() -> None:
    assert anthropic_endpoint().messages_url == "https://api.anthropic.example/v1/messages"
    direct = anthropic_endpoint(base_url="https://api.anthropic.example/v1/messages")
    assert direct.messages_url == "https://api.anthropic.example/v1/messages"


def test_transport_remains_protocol_agnostic() -> None:
    HttpxChatTransport(proxy_url=None)
