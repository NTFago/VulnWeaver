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

__all__ = [
    "AgentRunConflict",
    "ChatTransport",
    "HttpxChatTransport",
    "InMemoryAgentRunRecorder",
    "ModelCallResult",
    "ModelConfigurationError",
    "ModelEndpoint",
    "ModelGateway",
    "ModelGatewayError",
    "ModelGatewaySettings",
    "ModelOutputError",
    "ModelProtocolError",
    "ModelRoute",
    "ModelTier",
    "ModelTransportError",
    "RedactionPolicy",
    "ThinkingConfig",
    "TransportResponse",
]
