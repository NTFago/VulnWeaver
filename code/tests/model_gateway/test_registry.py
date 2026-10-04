"""Provider registry and per-agent binding resolution tests."""

from __future__ import annotations

import pytest
from vulnweaver_model_gateway import ModelAccessConfig, ModelTier


def provider(
    provider_id: str = "deepseek",
    *,
    model_ids: tuple[str, ...] = ("deepseek-chat",),
    enabled: bool = True,
    base_url: str = "https://api.deepseek.com/v1",
) -> dict[str, object]:
    return {
        "id": provider_id,
        "name": f"Provider {provider_id}",
        "base_url": base_url,
        "api_format": "openai-chat",
        "enabled": enabled,
        "models": [
            {
                "model_id": model_id,
                "context_window_tokens": 131072,
                "max_output_tokens": 8192,
            }
            for model_id in model_ids
        ],
    }


def settings_with(
    providers: list[dict[str, object]],
    bindings: dict[str, object] | None = None,
    keys: dict[str, str] | None = None,
) -> dict[str, object]:
    return {
        "model_providers": providers,
        "agent_model_bindings": bindings or {},
        "provider_api_keys": keys or {},
    }


def test_binding_resolves_to_endpoint_with_model_metadata() -> None:
    config = ModelAccessConfig.from_settings(
        settings_with(
            [provider()],
            {"audit": {"provider_id": "deepseek", "model_id": "deepseek-chat"}},
            {"deepseek": "key-1"},
        )
    )
    routes = config.resolve_routes()
    assert set(routes) == {"audit"}
    endpoint = routes["audit"].primary
    assert endpoint.name == "deepseek:deepseek-chat"
    assert endpoint.model_for(ModelTier.AUDIT) == "deepseek-chat"
    assert endpoint.context_window_tokens == 131072
    assert endpoint.max_output_tokens == 8192
    assert endpoint.api_key == "key-1"


def test_fallback_binding_resolves_into_route() -> None:
    config = ModelAccessConfig.from_settings(
        settings_with(
            [
                provider("primary-prov"),
                provider("fallback-prov", base_url="https://fallback.example/v1"),
            ],
            {
                "planning": {
                    "provider_id": "primary-prov",
                    "model_id": "deepseek-chat",
                    "fallback_provider_id": "fallback-prov",
                    "fallback_model_id": "deepseek-chat",
                }
            },
        )
    )
    route = config.resolve_routes()["planning"]
    assert route.primary.name == "primary-prov:deepseek-chat"
    assert route.fallback is not None
    assert route.fallback.name == "fallback-prov:deepseek-chat"


def test_disabled_provider_fails_loudly_at_build_time() -> None:
    config = ModelAccessConfig.from_settings(
        settings_with(
            [provider(enabled=False)],
            {"audit": {"provider_id": "deepseek", "model_id": "deepseek-chat"}},
        )
    )
    with pytest.raises(Exception, match="disabled provider"):
        config.resolve_routes()


def test_unknown_provider_or_model_fails_loudly() -> None:
    dangling = ModelAccessConfig.from_settings(
        settings_with(
            [provider()],
            {"audit": {"provider_id": "missing", "model_id": "deepseek-chat"}},
        )
    )
    with pytest.raises(Exception, match="unknown provider"):
        dangling.resolve_routes()
    unknown_model = ModelAccessConfig.from_settings(
        settings_with(
            [provider()],
            {"audit": {"provider_id": "deepseek", "model_id": "nope"}},
        )
    )
    with pytest.raises(Exception, match="does not list"):
        unknown_model.resolve_routes()


def test_legacy_alias_api_formats_are_accepted() -> None:
    config = ModelAccessConfig.from_settings(
        settings_with(
            [{**provider(), "api_format": "anthropic-messages"}],
            {"review": {"provider_id": "deepseek", "model_id": "deepseek-chat"}},
        )
    )
    assert config.resolve_routes()["review"].primary.wire_protocol == "anthropic"


def test_duplicate_provider_or_model_ids_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate provider id"):
        ModelAccessConfig.from_settings(settings_with([provider(), provider()]))
    with pytest.raises(ValueError, match="twice"):
        ModelAccessConfig.from_settings(settings_with([provider(model_ids=("a", "a"))]))


def test_invalid_provider_id_rejected() -> None:
    with pytest.raises(Exception, match="provider id"):
        ModelAccessConfig.from_settings(settings_with([{**provider(), "id": "Bad ID!"}]))


def test_legacy_custom_thinking_budget_is_not_forwarded() -> None:
    raw = provider()
    raw["models"] = [
        {
            "model_id": "reasoner",
            "thinking_mode": "custom",
            "thinking_budget_tokens": 512,
        }
    ]
    config = ModelAccessConfig.from_settings(
        settings_with([raw], {"audit": {"provider_id": "deepseek", "model_id": "reasoner"}})
    )
    endpoint = config.resolve_routes()["audit"].primary
    assert endpoint.thinking is not None
    assert endpoint.thinking.mode == "default"
    assert endpoint.thinking.budget_tokens is None


def test_malformed_stored_shapes_fail_loudly() -> None:
    with pytest.raises(Exception, match="must be a list"):
        ModelAccessConfig.from_settings({"model_providers": "nope"})
    with pytest.raises(Exception, match="must be a string"):
        ModelAccessConfig.from_settings(
            settings_with([provider()], {"audit": {"provider_id": 3, "model_id": "m"}})
        )


def test_empty_registry_is_valid_and_resolves_nothing() -> None:
    config = ModelAccessConfig.from_settings({})
    assert not config.has_bindings()
    assert config.resolve_routes() == {}
