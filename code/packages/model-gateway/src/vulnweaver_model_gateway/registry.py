"""Provider registry and per-agent model bindings.

The registry mirrors how end-user tools (cc-switch, dsh, ZCode) organize model
access: named **providers** carry the connection (base URL, API format, API
key, enable toggle) plus a **model list** with per-model metadata (context
window, physical output capacity, thinking), and each agent role binds to one
``(provider, model)`` pair with an optional fallback pair.

The registry is storage-agnostic: :meth:`ModelAccessConfig.from_settings`
parses the shape persisted in product settings, and :meth:`resolve_routes`
produces the gateway routes. Binding to a missing or disabled provider fails
loudly at build time so a typo never silently disables an agent's model.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import cast
from urllib.parse import urlparse

from vulnweaver_model_gateway.errors import ModelConfigurationError
from vulnweaver_model_gateway.gateway import (
    ModelEndpoint,
    ModelRoute,
    ThinkingConfig,
)

_PROVIDER_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_AGENT_ROLES = ("planning", "audit", "review", "report")
_API_FORMATS = ("openai-chat", "anthropic-messages", "openai-responses")


@dataclass(frozen=True, slots=True)
class ProviderModel:
    """One model offered by a provider, with the metadata the gateway needs."""

    model_id: str
    display_name: str = ""
    context_window_tokens: int = 0
    max_output_tokens: int = 0
    thinking_mode: str = "off"
    thinking_budget_tokens: int = 0
    thinking_effort: str | None = None
    thinking_style: str = "standard"


@dataclass(frozen=True, slots=True)
class ModelProvider:
    """One configured model provider (connection + model list).

    ``api_key`` is in-process routing data only; it must never be serialized
    back into settings or logs.
    """

    id: str
    name: str
    base_url: str
    api_format: str
    enabled: bool = True
    timeout_seconds: float = 0.0
    max_attempts: int = 0
    models: tuple[ProviderModel, ...] = ()
    api_key: str | None = None

    def model(self, model_id: str) -> ProviderModel | None:
        for model in self.models:
            if model.model_id == model_id:
                return model
        return None


@dataclass(frozen=True, slots=True)
class AgentBinding:
    """One agent role bound to a specific provider model."""

    role: str
    provider_id: str
    model_id: str
    fallback_provider_id: str | None = None
    fallback_model_id: str | None = None


@dataclass(frozen=True, slots=True)
class ModelAccessConfig:
    """Validated provider registry + agent bindings, resolvable to routes."""

    providers: tuple[ModelProvider, ...] = field(default_factory=tuple)
    bindings: tuple[AgentBinding, ...] = field(default_factory=tuple)
    default_timeout_seconds: float = 60.0
    default_max_attempts: int = 2

    def __post_init__(self) -> None:
        if self.default_timeout_seconds <= 0 or self.default_timeout_seconds > 3600:
            raise ValueError("default model timeout must be between 0 and 3600 seconds")
        if self.default_max_attempts < 1 or self.default_max_attempts > 8:
            raise ValueError("default model attempts must be between 1 and 8")
        seen: set[str] = set()
        for provider in self.providers:
            if not provider.id or not _PROVIDER_ID_PATTERN.match(provider.id):
                raise ValueError(
                    f"provider id {provider.id!r} must match {_PROVIDER_ID_PATTERN.pattern}"
                )
            if provider.id in seen:
                raise ValueError(f"duplicate provider id {provider.id!r}")
            seen.add(provider.id)
            if not provider.name:
                raise ValueError(f"provider {provider.id!r} requires a display name")
            parsed = urlparse(provider.base_url)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError(f"provider {provider.id!r} base_url must use http or https")
            if parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise ValueError(
                    f"provider {provider.id!r} base_url must not contain credentials or query data"
                )
            if provider.api_format not in _API_FORMATS:
                raise ValueError(f"provider {provider.id!r} has an unknown api_format")
            if provider.timeout_seconds < 0 or provider.timeout_seconds > 3600:
                raise ValueError(f"provider {provider.id!r} timeout is outside 0..3600 seconds")
            if provider.max_attempts < 0 or provider.max_attempts > 8:
                raise ValueError(f"provider {provider.id!r} attempts must be between 0 and 8")
            model_ids: set[str] = set()
            for model in provider.models:
                if not model.model_id or len(model.model_id) > 256:
                    raise ValueError(f"provider {provider.id!r} has a model with an empty id")
                if model.model_id in model_ids:
                    raise ValueError(
                        f"provider {provider.id!r} lists model {model.model_id!r} twice"
                    )
                model_ids.add(model.model_id)
                if model.thinking_mode not in {"off", "default", "custom"}:
                    raise ValueError(
                        f"provider {provider.id!r} model {model.model_id!r} has an unknown "
                        "thinking mode"
                    )
                if model.thinking_effort is not None and model.thinking_effort not in {
                    "none",
                    "minimal",
                    "low",
                    "medium",
                    "high",
                    "xhigh",
                    "max",
                }:
                    raise ValueError(
                        f"provider {provider.id!r} model {model.model_id!r} has invalid effort"
                    )
                if model.thinking_style not in {"standard", "deepseek", "kimi"}:
                    raise ValueError(f"model {model.model_id!r} has invalid thinking style")
                if (
                    model.thinking_style in {"deepseek", "kimi"}
                    and provider.api_format != "openai-chat"
                ):
                    raise ValueError("vendor thinking control requires OpenAI Chat")
                if model.thinking_style in {"deepseek", "kimi"} and model.thinking_effort not in {
                    None,
                    "low",
                    "high",
                    "max",
                }:
                    raise ValueError("vendor reasoning effort must be low, high or max")
                if model.thinking_style == "kimi":
                    if model.model_id not in {
                        "kimi-k3",
                        "kimi-k2.6",
                    } and not model.model_id.startswith("kimi-k2.7-code"):
                        raise ValueError("Kimi thinking control is not verified for this model")
                    if (
                        model.model_id == "kimi-k3" or model.model_id.startswith("kimi-k2.7-code")
                    ) and model.thinking_mode == "off":
                        raise ValueError("this Kimi model cannot disable thinking")
                    if model.model_id != "kimi-k3" and model.thinking_effort is not None:
                        raise ValueError("Kimi K2.x does not support reasoning_effort")
        roles_seen: set[str] = set()
        for binding in self.bindings:
            if binding.role not in _AGENT_ROLES:
                raise ValueError(f"unknown agent role {binding.role!r}")
            if binding.role in roles_seen:
                raise ValueError(f"duplicate binding for role {binding.role!r}")
            roles_seen.add(binding.role)
            if not binding.provider_id or not binding.model_id:
                raise ValueError(f"binding for {binding.role!r} must name provider and model")

    @classmethod
    def from_settings(
        cls,
        product_settings: Mapping[str, object],
        api_keys: Mapping[str, str] | None = None,
        *,
        default_timeout_seconds: float = 60.0,
        default_max_attempts: int = 2,
    ) -> ModelAccessConfig:
        """Parse the registry from stored product settings.

        Missing sections mean "nothing configured" and yield an empty registry;
        malformed values fail loudly so operators see the bad shape instead of a
        silently ignored model config.
        """

        keys: dict[str, str]
        if api_keys is not None:
            keys = dict(api_keys)
        else:
            # Default to the keys embedded in the stored settings, which is how
            # they persist; an explicit mapping lets callers keep secrets apart.
            raw_keys = product_settings.get("provider_api_keys")
            keys = (
                {
                    str(key_id): key_value
                    for key_id, key_value in cast(Mapping[str, object], raw_keys).items()
                    if isinstance(key_value, str)
                }
                if isinstance(raw_keys, Mapping)
                else {}
            )
        providers_raw = product_settings.get("model_providers")
        providers: list[ModelProvider] = []
        if providers_raw is not None:
            if not isinstance(providers_raw, list):
                raise ModelConfigurationError("stored model_providers must be a list")
            for entry in cast(list[object], providers_raw):
                if not isinstance(entry, Mapping):
                    raise ModelConfigurationError("stored model provider entries must be objects")
                providers.append(_parse_provider(cast(Mapping[str, object], entry), keys))
        bindings_raw = product_settings.get("agent_model_bindings")
        bindings: list[AgentBinding] = []
        if bindings_raw is not None:
            if not isinstance(bindings_raw, Mapping):
                raise ModelConfigurationError("stored agent_model_bindings must be an object")
            bindings_mapping = cast(Mapping[str, object], bindings_raw)
            for role in _AGENT_ROLES:
                binding_raw = bindings_mapping.get(role)
                if binding_raw is None:
                    continue
                if not isinstance(binding_raw, Mapping):
                    raise ModelConfigurationError(
                        f"stored agent_model_bindings.{role} must be an object"
                    )
                binding_source = cast(Mapping[str, object], binding_raw)
                fallback_provider = binding_source.get("fallback_provider_id")
                fallback_model = binding_source.get("fallback_model_id")
                if (fallback_provider is None) != (fallback_model is None):
                    raise ModelConfigurationError(
                        f"stored agent_model_bindings.{role} fallback must name both "
                        "provider and model"
                    )
                bindings.append(
                    AgentBinding(
                        role=role,
                        provider_id=_parse_str(binding_source, role, "provider_id"),
                        model_id=_parse_str(binding_source, role, "model_id"),
                        fallback_provider_id=(
                            fallback_provider if isinstance(fallback_provider, str) else None
                        ),
                        fallback_model_id=(
                            fallback_model if isinstance(fallback_model, str) else None
                        ),
                    )
                )
        return cls(
            providers=tuple(providers),
            bindings=tuple(bindings),
            default_timeout_seconds=default_timeout_seconds,
            default_max_attempts=default_max_attempts,
        )

    def has_bindings(self) -> bool:
        return bool(self.bindings)

    def provider(self, provider_id: str) -> ModelProvider | None:
        for provider in self.providers:
            if provider.id == provider_id:
                return provider
        return None

    def resolve_routes(self) -> dict[str, ModelRoute]:
        """Resolve one route per bound agent role.

        A binding whose provider or model is missing, or whose provider is
        disabled, raises instead of being skipped: the API validates bindings on
        save, so reaching this state means the stored settings were tampered
        with and the affected agent must not quietly lose its model.
        """

        routes: dict[str, ModelRoute] = {}
        for binding in self.bindings:
            primary = self._endpoint_for(binding.role, binding.provider_id, binding.model_id)
            fallback: ModelEndpoint | None = None
            if binding.fallback_provider_id and binding.fallback_model_id:
                fallback = self._endpoint_for(
                    f"{binding.role} fallback",
                    binding.fallback_provider_id,
                    binding.fallback_model_id,
                )
            routes[binding.role] = ModelRoute(primary=primary, fallback=fallback)
        return routes

    def _endpoint_for(self, role: str, provider_id: str, model_id: str) -> ModelEndpoint:
        provider = self.provider(provider_id)
        if provider is None:
            raise ModelConfigurationError(
                "agent binding references an unknown provider",
                details={"role": role, "provider_id": provider_id},
            )
        if not provider.enabled:
            raise ModelConfigurationError(
                "agent binding references a disabled provider",
                details={"role": role, "provider_id": provider_id},
            )
        model = provider.model(model_id)
        if model is None:
            raise ModelConfigurationError(
                "agent binding references a model the provider does not list",
                details={"role": role, "provider_id": provider_id, "model_id": model_id},
            )
        timeout = provider.timeout_seconds or self.default_timeout_seconds
        attempts = provider.max_attempts or self.default_max_attempts
        thinking: ThinkingConfig | None = None
        if (
            model.thinking_mode != "off"
            or model.thinking_effort
            or model.thinking_style != "standard"
        ):
            thinking = ThinkingConfig(
                mode="default" if model.thinking_mode == "custom" else model.thinking_mode,
                effort=model.thinking_effort,
                style=model.thinking_style,
            )
        return ModelEndpoint(
            name=f"{provider.id}:{model.model_id}",
            base_url=provider.base_url,
            models={role: model.model_id},
            api_key=provider.api_key,
            timeout_seconds=timeout,
            max_attempts=attempts,
            protocol=provider.api_format,
            context_window_tokens=model.context_window_tokens,
            max_output_tokens=model.max_output_tokens,
            thinking=thinking,
        )


def _parse_str(source: Mapping[str, object], role: str, key: str) -> str:
    value = source.get(key)
    if not isinstance(value, str) or not value:
        raise ModelConfigurationError(f"stored agent_model_bindings.{role}.{key} must be a string")
    return value


def _validated_model_int(
    source: Mapping[str, object], key: str, provider_id: str, model_id: str
) -> int:
    value = source.get(key, 0)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ModelConfigurationError(
            f"provider {provider_id!r} model {model_id!r} {key} is invalid"
        )
    return value


def _parse_provider(entry: Mapping[str, object], api_keys: Mapping[str, str]) -> ModelProvider:
    provider_id = entry.get("id")
    if not isinstance(provider_id, str) or not _PROVIDER_ID_PATTERN.match(provider_id):
        raise ModelConfigurationError("stored model provider id is missing or malformed")
    name = entry.get("name")
    base_url = entry.get("base_url")
    api_format = entry.get("api_format")
    if not isinstance(name, str) or not name:
        raise ModelConfigurationError(f"provider {provider_id!r} name must be a string")
    if not isinstance(base_url, str) or not base_url:
        raise ModelConfigurationError(f"provider {provider_id!r} base_url must be a string")
    if not isinstance(api_format, str) or api_format not in _API_FORMATS:
        raise ModelConfigurationError(f"provider {provider_id!r} api_format is unknown")
    enabled = entry.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ModelConfigurationError(f"provider {provider_id!r} enabled must be a boolean")
    timeout = entry.get("timeout_seconds", 0.0)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout < 0:
        raise ModelConfigurationError(f"provider {provider_id!r} timeout_seconds is invalid")
    attempts = entry.get("max_attempts", 0)
    if isinstance(attempts, bool) or not isinstance(attempts, int) or attempts < 0:
        raise ModelConfigurationError(f"provider {provider_id!r} max_attempts is invalid")
    models_raw = entry.get("models")
    if not isinstance(models_raw, list):
        raise ModelConfigurationError(f"provider {provider_id!r} models must be a list")
    models: list[ProviderModel] = []
    for model_raw in cast(list[object], models_raw):
        if not isinstance(model_raw, Mapping):
            raise ModelConfigurationError(f"provider {provider_id!r} model entries must be objects")
        model_source = cast(Mapping[str, object], model_raw)
        model_id = model_source.get("model_id")
        if not isinstance(model_id, str) or not model_id:
            raise ModelConfigurationError(
                f"provider {provider_id!r} has a model entry without model_id"
            )
        display = model_source.get("display_name", "")
        if display is not None and not isinstance(display, str):
            raise ModelConfigurationError(
                f"provider {provider_id!r} model {model_id!r} display_name must be a string"
            )
        context_window = _validated_model_int(
            model_source, "context_window_tokens", provider_id, model_id
        )
        max_output = _validated_model_int(model_source, "max_output_tokens", provider_id, model_id)
        thinking_budget = _validated_model_int(
            model_source, "thinking_budget_tokens", provider_id, model_id
        )
        thinking_mode = model_source.get("thinking_mode", "off")
        if not isinstance(thinking_mode, str) or thinking_mode not in {
            "off",
            "default",
            "custom",
        }:
            raise ModelConfigurationError(
                f"provider {provider_id!r} model {model_id!r} thinking_mode is unknown"
            )
        thinking_effort = model_source.get("thinking_effort")
        if thinking_effort is not None and not isinstance(thinking_effort, str):
            raise ModelConfigurationError(
                f"provider {provider_id!r} model {model_id!r} thinking_effort must be a string"
            )
        thinking_style = model_source.get("thinking_style", "standard")
        if not isinstance(thinking_style, str):
            raise ModelConfigurationError(
                f"provider {provider_id!r} model {model_id!r} thinking_style must be a string"
            )
        models.append(
            ProviderModel(
                model_id=model_id,
                display_name=display or "",
                context_window_tokens=context_window,
                max_output_tokens=max_output,
                thinking_mode=thinking_mode,
                thinking_budget_tokens=thinking_budget,
                thinking_effort=thinking_effort,
                thinking_style=thinking_style,
            )
        )
    return ModelProvider(
        id=provider_id,
        name=name,
        base_url=base_url,
        api_format=api_format,
        enabled=enabled,
        timeout_seconds=float(timeout),
        max_attempts=attempts,
        models=tuple(models),
        api_key=api_keys.get(provider_id),
    )
