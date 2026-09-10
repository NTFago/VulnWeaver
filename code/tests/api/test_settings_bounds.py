"""Settings the API accepts must be settings the worker's model gateway accepts.

The worker builds a ModelGateway from the stored settings on every assembly (re)build.
When the API's validation range is wider than the gateway's, a value the operator can save
makes that construction raise — and the worker then processes no job at all, which shows up
as tasks stuck in ``queued`` with no visible reason. These tests pin the two ranges together.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from vulnweaver_api.schemas import ProductSettingsBody
from vulnweaver_model_gateway import (
    ModelEndpoint,
    ModelGatewaySettings,
    ModelRoute,
    ModelTier,
)

# The widest values the settings API allows for the fields the gateway rule-checks.
API_MAXIMA = {
    "review_model_timeout_seconds": 600,
    "review_model_max_attempts": 8,
    "review_model_repair_attempts": 3,
    "review_model_min_interval_seconds": 60,
}


def test_gateway_accepts_the_widest_settings_the_api_allows() -> None:
    settings = ProductSettingsBody(**API_MAXIMA)
    gateway_settings = ModelGatewaySettings(
        routes={
            ModelTier.REVIEW: ModelRoute(
                primary=ModelEndpoint(
                    name="review-model",
                    base_url="https://example.invalid/v1",
                    models={ModelTier.REVIEW: "review-model"},
                    timeout_seconds=settings.review_model_timeout_seconds,
                    max_attempts=settings.review_model_max_attempts,
                )
            )
        },
        max_repair_attempts=settings.review_model_repair_attempts,
        min_request_interval_seconds=settings.review_model_min_interval_seconds,
    )
    assert gateway_settings.max_repair_attempts == 3


@pytest.mark.parametrize(
    "field,value",
    [
        ("review_model_repair_attempts", 4),
        ("review_model_max_attempts", 9),
        ("review_model_min_interval_seconds", 61),
        ("review_model_timeout_seconds", 601),
    ],
)
def test_api_rejects_settings_the_gateway_would_refuse(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        ProductSettingsBody(**{field: value})
