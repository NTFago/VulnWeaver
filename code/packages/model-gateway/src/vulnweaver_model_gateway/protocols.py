"""Protocol adapters for structured model requests and provider usage."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from vulnweaver_contracts import JsonObject, TokenUsage

from vulnweaver_model_gateway.errors import ModelProtocolError

if TYPE_CHECKING:
    from vulnweaver_model_gateway.gateway import ModelEndpoint


def response_object(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ModelProtocolError("model response body must be a JSON object", retryable=True)
    return cast(Mapping[str, object], value)


def _reasoning_effort(endpoint: ModelEndpoint) -> str | None:
    """Forward an explicitly selected effort without inventing a budget mapping."""
    return endpoint.thinking.effort if endpoint.thinking else None


def _anthropic_thinking(endpoint: ModelEndpoint) -> dict[str, object] | None:
    thinking = endpoint.thinking
    if thinking is None or thinking.mode == "off":
        return None
    return {"type": "adaptive"}


_JSON_INSTRUCTION = " Respond with a single JSON object and nothing else; no prose, no code fences."


def _openai_request(
    endpoint: ModelEndpoint,
    model: str,
    messages: Sequence[Mapping[str, str]],
    max_output_tokens: int | None,
) -> tuple[JsonObject, str, dict[str, str]]:
    payload: JsonObject = {
        "model": model,
        "messages": [dict(message) for message in messages],
        "response_format": {"type": "json_object"},
    }
    if endpoint.thinking is not None and endpoint.thinking.style == "deepseek":
        payload["thinking"] = {"type": "disabled" if endpoint.thinking.mode == "off" else "enabled"}
        # DeepSeek otherwise defaults to 8K/64K below its documented 384 KiTok
        # physical maximum. Ignore stale persisted metadata that may be lower.
        payload["max_tokens"] = 393_216
    if endpoint.thinking is not None and endpoint.thinking.style == "kimi" and model == "kimi-k2.6":
        payload["thinking"] = {"type": "disabled" if endpoint.thinking.mode == "off" else "enabled"}
    effort = _reasoning_effort(endpoint)
    if effort is not None:
        payload["reasoning_effort"] = effort
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if endpoint.api_key:
        headers["Authorization"] = f"Bearer {endpoint.api_key}"
    return payload, endpoint.chat_completions_url, headers


def _anthropic_request(
    endpoint: ModelEndpoint,
    model: str,
    messages: Sequence[Mapping[str, str]],
    max_output_tokens: int | None,
) -> tuple[JsonObject, str, dict[str, str]]:
    """Build a ``/v1/messages`` payload from the neutral chat messages."""

    system_parts = [
        str(message["content"]) for message in messages if str(message.get("role", "")) == "system"
    ]
    chat_messages = [
        {"role": str(message["role"]), "content": str(message["content"])}
        for message in messages
        if str(message.get("role", "")) != "system"
    ]
    if chat_messages and str(chat_messages[-1]["role"]) == "user":
        chat_messages[-1]["content"] = str(chat_messages[-1]["content"]) + _JSON_INSTRUCTION
    else:
        system_parts.append(_JSON_INSTRUCTION.strip())
    payload: dict[str, object] = {
        "model": model,
        # Messages requires max_tokens. This is the model's physical output
        # capability, never a user budget. Unknown models use the current
        # Claude family maximum; providers reject a value they do not support.
        "max_tokens": endpoint.max_output_tokens or 128_000,
        "messages": chat_messages,
    }
    if system_parts:
        payload["system"] = "\n\n".join(system_parts)
    thinking = _anthropic_thinking(endpoint)
    if thinking is not None:
        payload["thinking"] = thinking
    effort = _reasoning_effort(endpoint)
    if effort is not None:
        payload["output_config"] = {"effort": effort}
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "anthropic-version": "2023-06-01",
    }
    if endpoint.api_key:
        headers["x-api-key"] = endpoint.api_key
    return cast(JsonObject, payload), endpoint.messages_url, headers


def _openai_responses_request(
    endpoint: ModelEndpoint,
    model: str,
    messages: Sequence[Mapping[str, str]],
    max_output_tokens: int | None,
) -> tuple[JsonObject, str, dict[str, str]]:
    """Build a ``/responses`` payload from the neutral chat messages."""

    system_parts = [
        str(message["content"]) for message in messages if str(message.get("role", "")) == "system"
    ]
    input_items = [
        {"role": str(message["role"]), "content": str(message["content"])}
        for message in messages
        if str(message.get("role", "")) != "system"
    ]
    payload: dict[str, object] = {
        "model": model,
        "input": input_items,
        "text": {"format": {"type": "json_object"}},
    }
    if system_parts:
        payload["instructions"] = "\n\n".join(system_parts)
    effort = _reasoning_effort(endpoint)
    if effort is not None:
        payload["reasoning"] = {"effort": effort}
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if endpoint.api_key:
        headers["Authorization"] = f"Bearer {endpoint.api_key}"
    return cast(JsonObject, payload), endpoint.responses_url, headers


def _extract_openai_responses_response(body: Mapping[str, object]) -> tuple[str, TokenUsage]:
    status = body.get("status")
    if status == "incomplete":
        raise ModelProtocolError(
            "model response is incomplete (output budget exhausted before JSON completed)",
            details={"status": "incomplete"},
            retryable=False,
        )
    output_blocks = body.get("output")
    if not isinstance(output_blocks, list) or not output_blocks:
        raise ModelProtocolError("model response did not contain output", retryable=True)
    parts: list[str] = []
    for block in cast(list[object], output_blocks):
        if not isinstance(block, Mapping):
            continue
        block_mapping = cast(Mapping[str, object], block)
        if block_mapping.get("type") != "message":
            # Reasoning and tool-call items carry no answer text; skip them.
            continue
        content_blocks = block_mapping.get("content")
        if not isinstance(content_blocks, list):
            continue
        for content_block in cast(list[object], content_blocks):
            if not isinstance(content_block, Mapping):
                continue
            content_mapping = cast(Mapping[str, object], content_block)
            if content_mapping.get("type") == "output_text" and isinstance(
                content_mapping.get("text"), str
            ):
                parts.append(str(content_mapping["text"]))
    if not parts:
        raise ModelProtocolError("model response contained no text output", retryable=True)
    usage = _parse_usage(body.get("usage"), "openai-responses")
    return "".join(parts), usage


def _extract_anthropic_response(body: Mapping[str, object]) -> tuple[str, TokenUsage]:
    if body.get("stop_reason") in {"max_tokens", "model_context_window_exceeded"}:
        raise ModelProtocolError("model response stopped at its physical output limit")
    content_blocks = body.get("content")
    if not isinstance(content_blocks, list) or not content_blocks:
        raise ModelProtocolError("model response did not contain content", retryable=True)
    parts: list[str] = []
    for block in cast(list[object], content_blocks):
        if not isinstance(block, Mapping):
            continue
        block_mapping = cast(Mapping[str, object], block)
        # Extended-thinking blocks carry reasoning, not answer text; skip them.
        if block_mapping.get("type") == "text" and isinstance(block_mapping.get("text"), str):
            parts.append(str(block_mapping["text"]))
    if not parts:
        raise ModelProtocolError("model response contained no text content", retryable=True)
    usage_value = body.get("usage")
    usage = _parse_usage(usage_value, "anthropic")
    return "".join(parts), usage


def _extract_response(body: Mapping[str, object]) -> tuple[str, TokenUsage]:
    choices = body.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ModelProtocolError("model response did not contain choices", retryable=True)
    choices_list = cast(list[object], choices)
    choice = choices_list[0]
    if not isinstance(choice, Mapping):
        raise ModelProtocolError("model response choice is malformed", retryable=True)
    choice_mapping = cast(Mapping[str, object], choice)
    if choice_mapping.get("finish_reason") == "length":
        raise ModelProtocolError("model response stopped at its physical output limit")
    message_value = choice_mapping.get("message")
    if not isinstance(message_value, Mapping):
        raise ModelProtocolError("model response message content is malformed", retryable=True)
    message = cast(Mapping[str, object], message_value)
    content = message.get("content")
    if not isinstance(content, str):
        raise ModelProtocolError("model response message content is malformed", retryable=True)
    usage_value = body.get("usage")
    usage = _parse_usage(usage_value, "openai")
    return content, usage


def _parse_usage(value: object, protocol: str) -> TokenUsage:
    if value is None:
        return {"input_tokens": 0, "output_tokens": 0, "missing_usage_responses": 1}
    if not isinstance(value, Mapping):
        raise ModelProtocolError("model response usage is malformed", retryable=True)
    usage = cast(Mapping[str, object], value)
    input_key = "prompt_tokens" if protocol == "openai" else "input_tokens"
    output_key = "completion_tokens" if protocol == "openai" else "output_tokens"
    input_tokens = usage.get(input_key, 0)
    output_tokens = usage.get(output_key, 0)
    if not _nonnegative_int(input_tokens) or not _nonnegative_int(output_tokens):
        raise ModelProtocolError("model response token usage is malformed", retryable=True)
    input_count = cast(int, input_tokens)
    output_count = cast(int, output_tokens)
    result: TokenUsage = {"input_tokens": input_count, "output_tokens": output_count}
    if input_key not in usage or output_key not in usage:
        result["missing_usage_responses"] = 1
    if protocol == "anthropic":
        for source, target in (
            ("cache_creation_input_tokens", "cache_write_input_tokens"),
            ("cache_read_input_tokens", "cached_input_tokens"),
        ):
            count = _usage_count(usage, source)
            if count is not None:
                result[target] = count
                result["input_tokens"] += count
        details = usage.get("output_tokens_details")
        if isinstance(details, Mapping):
            count = _usage_count(cast(Mapping[str, object], details), "thinking_tokens")
            if count is not None:
                result["reasoning_output_tokens"] = count
    else:
        details = (
            usage.get("input_tokens_details")
            if protocol == "openai-responses"
            else usage.get("prompt_tokens_details")
        )
        if isinstance(details, Mapping):
            count = _usage_count(cast(Mapping[str, object], details), "cached_tokens")
            if count is not None:
                result["cached_input_tokens"] = count
            count = _usage_count(cast(Mapping[str, object], details), "cache_write_tokens")
            if count is not None:
                result["cache_write_input_tokens"] = count
        if protocol == "openai":
            count = _usage_count(usage, "prompt_cache_hit_tokens")
            if count is not None and "cached_input_tokens" not in result:
                result["cached_input_tokens"] = count
            count = _usage_count(usage, "cached_tokens")
            if count is not None and "cached_input_tokens" not in result:
                result["cached_input_tokens"] = count
        details = (
            usage.get("output_tokens_details")
            if protocol == "openai-responses"
            else usage.get("completion_tokens_details")
        )
        if isinstance(details, Mapping):
            count = _usage_count(cast(Mapping[str, object], details), "reasoning_tokens")
            if count is not None:
                result["reasoning_output_tokens"] = count
    if (
        result.get("cached_input_tokens", 0) + result.get("cache_write_input_tokens", 0)
        > result["input_tokens"]
        or result.get("reasoning_output_tokens", 0) > result["output_tokens"]
    ):
        raise ModelProtocolError("model response usage breakdown exceeds total", retryable=False)
    return result


def _usage_count(source: Mapping[str, object], key: str) -> int | None:
    value = source.get(key)
    if value is None:
        return None
    if not _nonnegative_int(value):
        raise ModelProtocolError("model response token usage is malformed", retryable=True)
    return cast(int, value)


def _nonnegative_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


@dataclass(frozen=True, slots=True)
class ModelProtocolAdapter:
    name: str
    build_request: Callable[
        [ModelEndpoint, str, Sequence[Mapping[str, str]], int | None],
        tuple[JsonObject, str, dict[str, str]],
    ]
    extract_response: Callable[[Mapping[str, object]], tuple[str, TokenUsage]]

    def parse_usage(self, value: object) -> TokenUsage:
        return _parse_usage(value, self.name)


_ADAPTERS = {
    "openai": ModelProtocolAdapter("openai", _openai_request, _extract_response),
    "anthropic": ModelProtocolAdapter("anthropic", _anthropic_request, _extract_anthropic_response),
    "openai-responses": ModelProtocolAdapter(
        "openai-responses", _openai_responses_request, _extract_openai_responses_response
    ),
}


def adapter_for(protocol: str) -> ModelProtocolAdapter:
    try:
        return _ADAPTERS[protocol]
    except KeyError as error:
        raise ModelProtocolError("model protocol has no adapter") from error
