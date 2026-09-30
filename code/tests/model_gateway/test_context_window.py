"""The window fit is the last-resort tier of the agent context strategy.

Callers keep prompts bounded upstream (agent-loop journal caps); when they
still overflow a configured context window the gateway trims message bodies —
never system messages — and records what it did (ADR-035).
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import cast

from vulnweaver_contracts import JsonObject
from vulnweaver_model_gateway import (
    InMemoryAgentRunRecorder,
    ModelEndpoint,
    ModelGateway,
    ModelGatewaySettings,
    ModelRoute,
    ModelTier,
    TransportResponse,
)
from vulnweaver_model_gateway.gateway import _TRIM_MARKER, _fit_context_window

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)

REVIEW_CONTENT = (
    '{"schema_version":"1.0.0","id":"review:probe","finding_id":"finding:probe",'
    '"outcome":"unverifiable","rationale":"probe","model":"review",'
    '"supersedes_review_id":null,"created_at":"2026-09-09T00:00:00Z"}'
)


class FakeTransport:
    def __init__(self, responses: list[object]) -> None:
        self.responses = responses
        self.requests: list[JsonObject] = []

    async def post_json(
        self,
        url: str,
        headers: Mapping[str, str],
        payload: JsonObject,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> TransportResponse:
        del url, headers, timeout_seconds, max_response_bytes
        self.requests.append(payload)
        response = self.responses.pop(0)
        assert isinstance(response, TransportResponse)
        return response


def endpoint(*, window: int = 0, max_output: int = 0) -> ModelEndpoint:
    return ModelEndpoint(
        name="remote",
        base_url="https://models.example/v1",
        models={ModelTier.AUDIT: "audit-model"},
        api_key="secret-key",
        max_attempts=1,
        retry_backoff_seconds=0,
        context_window_tokens=window,
        max_output_tokens=max_output,
    )


def test_unset_window_is_a_noop() -> None:
    messages = [
        {"role": "system", "content": "s" * 2_000},
        {"role": "user", "content": "u" * 50_000},
    ]

    fitted, decisions = _fit_context_window(endpoint(window=0), messages, None)

    assert fitted == messages
    assert decisions == ()


def test_under_budget_is_untouched() -> None:
    messages = [{"role": "user", "content": "u" * 400}]

    fitted, decisions = _fit_context_window(endpoint(window=4_000), messages, None)

    assert fitted == messages
    assert decisions == ()


def test_over_budget_pins_system_messages_and_trims_the_rest() -> None:
    # The system message is the largest on purpose: without pinning it would be
    # the first thing trimmed.
    system = "instructions " * 1_000
    user = "observation " * 200
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]

    fitted, decisions = _fit_context_window(endpoint(window=1_000), messages, None)

    assert fitted[0]["content"] == system
    assert _TRIM_MARKER in fitted[1]["content"]
    assert decisions and decisions[0][0] == "context_window_trimmed"


def test_trim_keeps_head_and_tail_anchors() -> None:
    user = "HEAD-ANCHERED-OPENING " + "filler " * 4_000 + "TAIL-ANCHERED-ENDING"
    messages = [
        {"role": "system", "content": "instructions"},
        {"role": "user", "content": user},
    ]

    fitted, _ = _fit_context_window(endpoint(window=1_000), messages, None)

    trimmed = fitted[1]["content"]
    assert trimmed.startswith("HEAD-ANCHERED-OPENING")
    assert trimmed.endswith("TAIL-ANCHERED-ENDING")
    assert len(trimmed) < len(user)


def test_nothing_trimmable_sends_as_is_without_a_decision() -> None:
    messages = [
        {"role": "system", "content": "s" * 20_000},
        {"role": "system", "content": "more instructions"},
    ]

    fitted, decisions = _fit_context_window(endpoint(window=1_000), messages, None)

    assert fitted == messages
    assert decisions == ()


def test_trim_reaches_the_transport_and_is_recorded_on_the_run() -> None:
    transport = FakeTransport(
        [
            TransportResponse(
                200,
                {
                    "choices": [{"message": {"content": REVIEW_CONTENT}}],
                    "usage": {"prompt_tokens": 4, "completion_tokens": 3},
                },
            )
        ]
    )
    recorder = InMemoryAgentRunRecorder()
    gateway = ModelGateway(
        ModelGatewaySettings(
            routes={ModelTier.AUDIT: ModelRoute(primary=endpoint(window=1_000))},
            max_repair_attempts=0,
        ),
        transport=transport,
        recorder=recorder,
        clock=lambda: NOW,
        monotonic=lambda: 10.0,
    )

    result = asyncio.run(
        gateway.complete_structured(
            tier=ModelTier.AUDIT,
            task_id="task:trim",
            run_id="run:trim",
            messages=[
                {"role": "system", "content": "instructions"},
                {"role": "user", "content": "observation " * 2_000},
            ],
            output_contract="Review",
        )
    )

    assert result.succeeded
    sent_messages = cast(list[JsonObject], transport.requests[0]["messages"])
    assert _TRIM_MARKER in str(sent_messages[1]["content"])
    decisions = [record["decision"] for record in result.agent_run["decisions"]]
    assert "context_window_trimmed" in decisions
