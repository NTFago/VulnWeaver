"""Streaming transport tests: SSE reassembly into the non-streaming body."""

from __future__ import annotations

import pytest
from vulnweaver_model_gateway import ModelEndpoint, ModelTier
from vulnweaver_model_gateway.errors import ModelProtocolError
from vulnweaver_model_gateway.gateway import HttpxChatTransport, _SseResponseAggregator
from vulnweaver_model_gateway.protocols import adapter_for


def stream_lines() -> list[str]:
    return [
        "event: message_start",
        'data: {"type":"message_start","message":{"id":"msg_1","role":"assistant",'
        '"model":"glm-5.3-anthropic","content":[],"usage":{"input_tokens":120,'
        '"output_tokens":1,"cache_read_input_tokens":10}}}',
        "event: ping",
        'data: {"type": "ping"}',
        "event: content_block_start",
        'data: {"type":"content_block_start","index":0,'
        '"content_block":{"type":"thinking","thinking":""}}',
        'data: {"type":"content_block_delta","index":0,'
        '"delta":{"type":"thinking_delta","thinking":"step "}}',
        'data: {"type":"content_block_delta","index":0,'
        '"delta":{"type":"thinking_delta","thinking":"one"}}',
        "event: content_block_start",
        'data: {"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}',
        'data: {"type":"content_block_delta","index":1,'
        '"delta":{"type":"text_delta","text":"{\\"ok\\": true}"}}',
        "event: content_block_stop",
        'data: {"type":"content_block_stop","index":1}',
        "event: message_delta",
        'data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},'
        '"usage":{"output_tokens":42}}',
        "event: message_stop",
        'data: {"type":"message_stop"}',
        "",
    ]


def test_aggregator_reassembles_text_thinking_and_final_usage() -> None:
    aggregator = _SseResponseAggregator(max_response_bytes=64 * 1024)
    for line in stream_lines():
        aggregator.feed_line(line)
    body = aggregator.finish()
    assert body["stop_reason"] == "end_turn"
    # message_delta's output_tokens is the final cumulative count, not an
    # increment over message_start's placeholder.
    assert body["usage"] == {
        "input_tokens": 120,
        "output_tokens": 42,
        "cache_read_input_tokens": 10,
    }
    blocks = [block for block in body["content"] if block]
    assert {"type": "thinking", "thinking": "step one"} in blocks
    assert {"type": "text", "text": '{"ok": true}'} in blocks


def test_aggregator_ignores_noise_lines_and_unknown_events() -> None:
    aggregator = _SseResponseAggregator(max_response_bytes=64 * 1024)
    for line in [
        ": comment",
        "",
        "event: something_new",
        "data: not json at all",
        "data: [DONE]",
        'data: {"type":"vendor_future_event","payload":{"x":1}}',
        *stream_lines(),
    ]:
        aggregator.feed_line(line)
    assert aggregator.finish()["stop_reason"] == "end_turn"


def test_aggregator_enforces_response_size_cap() -> None:
    aggregator = _SseResponseAggregator(max_response_bytes=64)
    with pytest.raises(ModelProtocolError) as excinfo:
        for line in stream_lines():
            aggregator.feed_line(line)
    assert excinfo.value.retryable is False


def test_aggregator_maps_stream_error_event_to_retryable_protocol_error() -> None:
    aggregator = _SseResponseAggregator(max_response_bytes=64 * 1024)
    with pytest.raises(ModelProtocolError) as excinfo:
        for line in [
            'data: {"type":"message_start","message":{"usage":{}}}',
            'data: {"type":"error","error":{"type":"overloaded_error","message":"slow down"}}',
        ]:
            aggregator.feed_line(line)
    assert excinfo.value.retryable is True
    assert "slow down" in str(excinfo.value)


def test_aggregator_requires_message_stop() -> None:
    aggregator = _SseResponseAggregator(max_response_bytes=64 * 1024)
    aggregator.feed_line('data: {"type":"message_start","message":{"usage":{}}}')
    with pytest.raises(ModelProtocolError) as excinfo:
        aggregator.finish()
    assert excinfo.value.retryable is True


def test_anthropic_request_declares_streaming() -> None:
    endpoint = ModelEndpoint(
        name="glm",
        base_url="https://llm.example/v1",
        models={ModelTier.AUDIT: "glm-5.3-anthropic"},
        api_key="secret",
        max_attempts=1,
        retry_backoff_seconds=0.0,
        protocol="anthropic",
    )
    payload, url, _ = adapter_for("anthropic").build_request(
        endpoint, "glm-5.3-anthropic", [{"role": "user", "content": "hi"}], None
    )
    assert url == "https://llm.example/v1/messages"
    assert payload["stream"] is True


@pytest.mark.anyio
async def test_streaming_transport_decodes_sse_into_transport_response() -> None:
    import json

    import httpx

    def sse_handler(request: httpx.Request) -> httpx.Response:
        assert json.loads(request.content)["stream"] is True
        body = "".join(f"{line}\n" for line in stream_lines())
        return httpx.Response(
            200, content=body.encode(), headers={"content-type": "text/event-stream"}
        )

    transport = HttpxChatTransport()
    real_client_factory = httpx.AsyncClient

    class PatchedAsyncClient(real_client_factory):
        def __init__(self, **kwargs: object) -> None:
            kwargs["transport"] = httpx.MockTransport(sse_handler)
            super().__init__(**kwargs)

    httpx.AsyncClient = PatchedAsyncClient  # type: ignore[misc]
    try:
        response = await transport.post_json(
            "https://llm.example/v1/messages",
            {"x-api-key": "secret"},
            {"model": "glm-5.3-anthropic", "stream": True, "messages": []},
            timeout_seconds=30.0,
            max_response_bytes=64 * 1024,
        )
    finally:
        httpx.AsyncClient = real_client_factory
    assert response.status_code == 200
    body = response.body
    assert isinstance(body, dict)
    assert body["stop_reason"] == "end_turn"


@pytest.mark.anyio
async def test_streaming_transport_passes_error_status_through() -> None:
    import httpx

    def error_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": {"message": "bad key"}})

    transport = HttpxChatTransport()
    real_client_factory = httpx.AsyncClient

    class PatchedAsyncClient(real_client_factory):
        def __init__(self, **kwargs: object) -> None:
            kwargs["transport"] = httpx.MockTransport(error_handler)
            super().__init__(**kwargs)

    httpx.AsyncClient = PatchedAsyncClient  # type: ignore[misc]
    try:
        response = await transport.post_json(
            "https://llm.example/v1/messages",
            {"x-api-key": "wrong"},
            {"model": "glm-5.3-anthropic", "stream": True, "messages": []},
            timeout_seconds=30.0,
            max_response_bytes=64 * 1024,
        )
    finally:
        httpx.AsyncClient = real_client_factory
    assert response.status_code == 401
