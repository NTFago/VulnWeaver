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
from vulnweaver_model_gateway.protocols import _reasoning_effort

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
    assert payload["max_tokens"] == 128000  # Messages requires a physical model maximum
    # usage maps from Anthropic's vocabulary into the recorded AgentRun
    token_usage = result.agent_run["token_usage"]
    assert isinstance(token_usage, dict)
    assert token_usage["input_tokens"] == 7
    assert token_usage["output_tokens"] == 11


@pytest.mark.anyio
async def test_legacy_anthropic_budget_is_ignored_in_favor_of_adaptive_thinking() -> None:
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
    assert payload["thinking"] == {"type": "adaptive"}
    assert "budget_tokens" not in str(payload)


def test_openai_reasoning_effort_is_explicit() -> None:
    low = ModelEndpoint(
        name="m",
        base_url="https://models.example/v1",
        models={ModelTier.REVIEW: "r"},
        thinking=ThinkingConfig(mode="default", effort="low"),
    )
    medium = ModelEndpoint(
        name="m",
        base_url="https://models.example/v1",
        models={ModelTier.REVIEW: "r"},
        thinking=ThinkingConfig(mode="default", effort="xhigh"),
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
    assert _reasoning_effort(medium) == "xhigh"
    assert _reasoning_effort(high) is None
    assert _reasoning_effort(off) is None


def test_thinking_config_rejects_invalid_modes_and_effort() -> None:
    with pytest.raises(ValueError, match="thinking mode"):
        ThinkingConfig(mode="yolo")
    with pytest.raises(ValueError, match="effort"):
        ThinkingConfig(mode="default", effort="turbo")
    with pytest.raises(ValueError, match="negative"):
        ThinkingConfig(mode="custom", budget_tokens=-1)


def test_unknown_protocol_rejected() -> None:
    with pytest.raises(ValueError, match="protocol"):
        ModelEndpoint(
            name="m",
            base_url="https://models.example/v1",
            models={ModelTier.REVIEW: "r"},
            protocol="gemini",
        )


@pytest.mark.anyio
async def test_context_window_trims_oversized_input_instead_of_rejecting() -> None:
    transport = FakeTransport([anthropic_response('{"ok": true}')])
    gateway = ModelGateway(
        ModelGatewaySettings(
            routes={ModelTier.AUDIT: ModelRoute(anthropic_endpoint(context_window_tokens=200))},
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
    # The oversized message is trimmed to fit and the request proceeds.
    assert result.succeeded
    _, _, payload = transport.requests[0]
    messages = cast(list[dict[str, str]], payload["messages"])
    assert len(messages) == 1
    sent = messages[0]["content"]
    assert "[context trimmed]" in sent
    # Reserve is window // 4 tokens, so the content is bounded well below 2000 chars.
    assert len(sent) < 2000
    decisions = [str(decision["decision"]) for decision in result.agent_run["decisions"]]
    assert "context_window_trimmed" in decisions


def test_anthropic_messages_url_appends_to_v1_root() -> None:
    assert anthropic_endpoint().messages_url == "https://api.anthropic.example/v1/messages"
    direct = anthropic_endpoint(base_url="https://api.anthropic.example/v1/messages")
    assert direct.messages_url == "https://api.anthropic.example/v1/messages"


def test_transport_remains_protocol_agnostic() -> None:
    HttpxChatTransport(proxy_url=None)


def responses_endpoint(**overrides: object) -> ModelEndpoint:
    values: dict[str, object] = {
        "name": "responses-probe",
        "base_url": "https://gateway.example/v1",
        "models": {ModelTier.AUDIT: "reasoner-x"},
        "api_key": "responses-secret",
        "max_attempts": 1,
        "retry_backoff_seconds": 0.0,
        "protocol": "openai-responses",
    }
    values.update(overrides)
    return ModelEndpoint(**values)  # type: ignore[arg-type]


def responses_response(text: str, *, status: str = "completed") -> TransportResponse:
    return TransportResponse(
        200,
        {
            "status": status,
            "output": [
                {"type": "reasoning", "summary": []},
                {
                    "type": "message",
                    "content": [{"type": "output_text", "text": text}],
                },
            ],
            "usage": {"input_tokens": 5, "output_tokens": 9},
        },
    )


@pytest.mark.anyio
async def test_openai_responses_wire_format_round_trip() -> None:
    transport = FakeTransport([responses_response('{"ok": true}')])
    gateway = ModelGateway(
        ModelGatewaySettings(
            routes={ModelTier.AUDIT: ModelRoute(responses_endpoint())},
            max_repair_attempts=0,
        ),
        transport=transport,
    )
    result = await gateway.complete_structured(
        tier=ModelTier.AUDIT,
        task_id="task:responses",
        run_id="run:responses",
        messages=[
            {"role": "system", "content": "You audit code."},
            {"role": "user", "content": "Return JSON."},
        ],
        output_contract="JsonObject",
    )
    assert result.succeeded
    url, headers, payload = transport.requests[0]
    assert url == "https://gateway.example/v1/responses"
    assert headers["Authorization"] == "Bearer responses-secret"
    assert payload["model"] == "reasoner-x"
    assert payload["instructions"] == "You audit code."
    assert payload["input"] == [{"role": "user", "content": "Return JSON."}]
    assert payload["text"] == {"format": {"type": "json_object"}}
    token_usage = result.agent_run["token_usage"]
    assert isinstance(token_usage, dict)
    assert token_usage["input_tokens"] == 5
    assert token_usage["output_tokens"] == 9


@pytest.mark.anyio
async def test_openai_responses_incomplete_output_is_not_retried() -> None:
    transport = FakeTransport([responses_response('{"ok":', status="incomplete")])
    gateway = ModelGateway(
        ModelGatewaySettings(
            routes={ModelTier.AUDIT: ModelRoute(responses_endpoint(max_attempts=3))},
            max_repair_attempts=0,
        ),
        transport=transport,
    )
    result = await gateway.complete_structured(
        tier=ModelTier.AUDIT,
        task_id="task:responses-incomplete",
        run_id="run:responses-incomplete",
        messages=[{"role": "user", "content": "Return JSON."}],
        output_contract="JsonObject",
    )
    assert not result.succeeded
    assert result.failure is not None
    assert result.failure["code"] == "model_protocol_error"
    assert len(transport.requests) == 1


@pytest.mark.anyio
async def test_endpoint_max_output_tokens_shapes_anthropic_default() -> None:
    transport = FakeTransport([anthropic_response('{"ok": true}')])
    gateway = ModelGateway(
        ModelGatewaySettings(
            routes={ModelTier.AUDIT: ModelRoute(anthropic_endpoint(max_output_tokens=16384))},
            max_repair_attempts=0,
        ),
        transport=transport,
    )
    result = await gateway.complete_structured(
        tier=ModelTier.AUDIT,
        task_id="task:max-output",
        run_id="run:max-output",
        messages=[{"role": "user", "content": "Return JSON."}],
        output_contract="JsonObject",
    )
    assert result.succeeded
    payload = cast(JsonObject, transport.requests[0][2])
    assert payload["max_tokens"] == 16384


def test_protocol_aliases_normalize_to_wire_protocols() -> None:
    assert (
        ModelEndpoint(
            name="m",
            base_url="https://models.example/v1",
            models={ModelTier.REVIEW: "r"},
            protocol="openai-chat",
        ).wire_protocol
        == "openai"
    )
    assert (
        ModelEndpoint(
            name="m",
            base_url="https://models.example/v1",
            models={ModelTier.REVIEW: "r"},
            protocol="anthropic-messages",
        ).wire_protocol
        == "anthropic"
    )
    assert (
        ModelEndpoint(
            name="m",
            base_url="https://models.example/v1",
            models={ModelTier.REVIEW: "r"},
            protocol="openai-responses",
        ).wire_protocol
        == "openai-responses"
    )


def test_extended_timeout_cap_allows_long_reasoning_requests() -> None:
    ModelEndpoint(
        name="m",
        base_url="https://models.example/v1",
        models={ModelTier.REVIEW: "r"},
        timeout_seconds=1800,
    )
    with pytest.raises(ValueError, match="timeout"):
        ModelEndpoint(
            name="m",
            base_url="https://models.example/v1",
            models={ModelTier.REVIEW: "r"},
            timeout_seconds=3601,
        )


@pytest.mark.anyio
async def test_anthropic_adaptive_effort_and_cache_accounting() -> None:
    body = anthropic_response('{"ok": true}').body
    assert isinstance(body, dict)
    body["usage"] = {
        "input_tokens": 7,
        "cache_creation_input_tokens": 13,
        "cache_read_input_tokens": 19,
        "output_tokens": 23,
        "output_tokens_details": {"thinking_tokens": 11},
    }
    transport = FakeTransport([TransportResponse(200, body)])
    gateway = ModelGateway(
        ModelGatewaySettings(
            routes={
                ModelTier.AUDIT: ModelRoute(
                    anthropic_endpoint(
                        thinking=ThinkingConfig(mode="default", effort="xhigh"),
                        max_output_tokens=128000,
                    )
                )
            },
            max_repair_attempts=0,
        ),
        transport=transport,
    )
    result = await gateway.complete_structured(
        tier=ModelTier.AUDIT,
        task_id="task:usage",
        run_id="run:usage",
        messages=[{"role": "user", "content": "Return JSON."}],
        output_contract="JsonObject",
    )
    assert result.succeeded
    payload = transport.requests[0][2]
    assert payload["thinking"] == {"type": "adaptive"}
    assert payload["output_config"] == {"effort": "xhigh"}
    assert result.agent_run["token_usage"] == {
        "input_tokens": 39,
        "output_tokens": 23,
        "cached_input_tokens": 19,
        "cache_write_input_tokens": 13,
        "reasoning_output_tokens": 11,
    }


@pytest.mark.anyio
async def test_responses_effort_and_incomplete_usage_are_recorded() -> None:
    body = responses_response('{"ok":', status="incomplete").body
    assert isinstance(body, dict)
    body["usage"] = {
        "input_tokens": 31,
        "input_tokens_details": {"cached_tokens": 7},
        "output_tokens": 101,
        "output_tokens_details": {"reasoning_tokens": 97},
    }
    transport = FakeTransport([TransportResponse(200, body)])
    gateway = ModelGateway(
        ModelGatewaySettings(
            routes={
                ModelTier.AUDIT: ModelRoute(
                    responses_endpoint(
                        thinking=ThinkingConfig(mode="default", effort="xhigh"),
                    )
                )
            },
            max_repair_attempts=0,
        ),
        transport=transport,
    )
    result = await gateway.complete_structured(
        tier=ModelTier.AUDIT,
        task_id="task:incomplete",
        run_id="run:incomplete-usage",
        messages=[{"role": "user", "content": "Return JSON."}],
        output_contract="JsonObject",
    )
    assert not result.succeeded
    assert transport.requests[0][2]["reasoning"] == {"effort": "xhigh"}
    assert "max_output_tokens" not in transport.requests[0][2]
    assert result.agent_run["token_usage"] == {
        "input_tokens": 31,
        "output_tokens": 101,
        "cached_input_tokens": 7,
        "reasoning_output_tokens": 97,
    }


@pytest.mark.anyio
async def test_vendor_chat_thinking_controls_are_distinct() -> None:
    for model, style, mode, effort, expected in (
        (
            "deepseek-flash",
            "deepseek",
            "default",
            "high",
            {"thinking": {"type": "enabled"}, "reasoning_effort": "high"},
        ),
        ("kimi-k3", "kimi", "default", "high", {"reasoning_effort": "high"}),
        ("kimi-k2.6", "kimi", "off", None, {"thinking": {"type": "disabled"}}),
    ):
        transport = FakeTransport(
            [
                TransportResponse(
                    200,
                    {
                        "choices": [{"message": {"content": '{"ok": true}'}}],
                        "usage": {"prompt_tokens": 3, "completion_tokens": 5},
                    },
                )
            ]
        )
        endpoint = ModelEndpoint(
            name=style,
            base_url="https://vendor.example/v1",
            models={ModelTier.AUDIT: model},
            thinking=ThinkingConfig(mode=mode, effort=effort, style=style),
        )
        gateway = ModelGateway(
            ModelGatewaySettings(
                routes={ModelTier.AUDIT: ModelRoute(endpoint)},
                max_repair_attempts=0,
            ),
            transport=transport,
        )
        result = await gateway.complete_structured(
            tier=ModelTier.AUDIT,
            task_id="task:vendor",
            run_id=f"run:{model}",
            messages=[{"role": "user", "content": "Return JSON."}],
            output_contract="JsonObject",
        )
        assert result.succeeded
        payload = transport.requests[0][2]
        for key, value in expected.items():
            assert payload[key] == value
        if model == "kimi-k3":
            assert "thinking" not in payload
        if style == "kimi":
            assert "max_tokens" not in payload
        else:
            assert payload["max_tokens"] == 393216


@pytest.mark.anyio
async def test_deepseek_uses_physical_maximum_and_counts_cache_and_reasoning() -> None:
    transport = FakeTransport(
        [
            TransportResponse(
                200,
                {
                    "choices": [{"message": {"content": '{"ok": true}'}}],
                    "usage": {
                        "prompt_tokens": 41,
                        "completion_tokens": 53,
                        "prompt_cache_hit_tokens": 11,
                        "completion_tokens_details": {"reasoning_tokens": 37},
                    },
                },
            )
        ]
    )
    endpoint = ModelEndpoint(
        name="deepseek",
        base_url="https://api.deepseek.com",
        models={ModelTier.AUDIT: "deepseek-flash"},
        max_output_tokens=384000,
        thinking=ThinkingConfig(mode="default", effort="max", style="deepseek"),
    )
    gateway = ModelGateway(
        ModelGatewaySettings(
            routes={ModelTier.AUDIT: ModelRoute(endpoint)},
            max_repair_attempts=0,
        ),
        transport=transport,
    )
    result = await gateway.complete_structured(
        tier=ModelTier.AUDIT,
        task_id="task:deepseek",
        run_id="run:deepseek",
        messages=[{"role": "user", "content": "Return JSON."}],
        output_contract="JsonObject",
    )
    assert result.succeeded
    assert transport.requests[0][2]["max_tokens"] == 393216
    assert result.agent_run["token_usage"] == {
        "input_tokens": 41,
        "output_tokens": 53,
        "cached_input_tokens": 11,
        "reasoning_output_tokens": 37,
    }


@pytest.mark.anyio
async def test_truncated_chat_output_retains_reported_usage() -> None:
    transport = FakeTransport(
        [
            TransportResponse(
                200,
                {
                    "choices": [
                        {"finish_reason": "length", "message": {"content": '{"ok": true}'}}
                    ],
                    "usage": {"prompt_tokens": 9, "completion_tokens": 15},
                },
            )
        ]
    )
    gateway = ModelGateway(
        ModelGatewaySettings(
            routes={
                ModelTier.AUDIT: ModelRoute(
                    ModelEndpoint(
                        name="chat",
                        base_url="https://chat.example/v1",
                        models={ModelTier.AUDIT: "chat-model"},
                    )
                )
            },
            max_repair_attempts=0,
        ),
        transport=transport,
    )
    result = await gateway.complete_structured(
        tier=ModelTier.AUDIT,
        task_id="task:truncated",
        run_id="run:truncated",
        messages=[{"role": "user", "content": "Return JSON."}],
        output_contract="JsonObject",
    )
    assert not result.succeeded
    assert result.agent_run["token_usage"] == {"input_tokens": 9, "output_tokens": 15}


def test_kimi_rejects_unsupported_intensity_and_disabling_always_on_models() -> None:
    for model, thinking in (
        ("kimi-k3", ThinkingConfig(mode="off", style="kimi")),
        ("kimi-k2.7-code", ThinkingConfig(mode="off", style="kimi")),
        ("kimi-k2.6", ThinkingConfig(mode="default", effort="high", style="kimi")),
    ):
        with pytest.raises(ValueError, match="Kimi"):
            ModelEndpoint(
                name="kimi",
                base_url="https://vendor.example/v1",
                models={ModelTier.AUDIT: model},
                thinking=thinking,
            )
