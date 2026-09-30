"""Replaceable OpenAI-compatible model access for VulnWeaver."""

from vulnweaver_model_gateway.errors import (
    AgentRunConflict,
    ModelConfigurationError,
    ModelGatewayError,
    ModelOutputError,
    ModelProtocolError,
    ModelTransportError,
)
from vulnweaver_model_gateway.gateway import (
    ChatTransport,
    HttpxChatTransport,
    InMemoryAgentRunRecorder,
    ModelCallResult,
    ModelEndpoint,
    ModelGateway,
    ModelGatewaySettings,
    ModelRoute,
    ModelTier,
    RedactionPolicy,
    ThinkingConfig,
    TransportResponse,
)
from vulnweaver_model_gateway.registry import (
    AgentBinding,
    ModelAccessConfig,
    ModelProvider,
    ProviderModel,
)

__all__ = [
    "AgentBinding",
    "AgentRunConflict",
    "ChatTransport",
    "HttpxChatTransport",
    "InMemoryAgentRunRecorder",
    "ModelAccessConfig",
    "ModelCallResult",
    "ModelConfigurationError",
    "ModelEndpoint",
    "ModelGateway",
    "ModelGatewayError",
    "ModelGatewaySettings",
    "ModelOutputError",
    "ModelProtocolError",
    "ModelProvider",
    "ModelRoute",
    "ModelTier",
    "ModelTransportError",
    "ProviderModel",
    "RedactionPolicy",
    "ThinkingConfig",
    "TransportResponse",
]
