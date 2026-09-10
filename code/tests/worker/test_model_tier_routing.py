"""Legacy model settings must keep every tier the pipeline actually calls routable.

The analysis pipeline asks the gateway for the REVIEW, AUDIT and PLANNING tiers
(planning, reverse analysis, key-logic confirmation, exploit generation and
harness generation all use PLANNING). Deployments that only configure the legacy
review fields must therefore still get a route for all three; per-tier settings
take precedence when they exist.
"""

from __future__ import annotations

from vulnweaver_analysis_worker.main import _tier_endpoint
from vulnweaver_model_gateway import ModelTier

LEGACY_SETTINGS: dict[str, object] = {
    "review_model_base_url": "https://legacy.invalid/v1",
    "review_model_name": "legacy-review-model",
    "review_model_api_key": "secret",
}


def test_legacy_review_settings_route_review_audit_and_planning() -> None:
    for tier in (ModelTier.REVIEW, ModelTier.AUDIT, ModelTier.PLANNING):
        endpoint = _tier_endpoint(tier, {}, {}, LEGACY_SETTINGS)
        assert endpoint is not None, f"{tier} must keep a legacy route"
        assert endpoint.base_url == "https://legacy.invalid/v1"


def test_tier_without_configuration_is_not_routed() -> None:
    # REPORT has no consumer; the gateway must not invent a route for it.
    assert _tier_endpoint(ModelTier.REPORT, {}, {}, LEGACY_SETTINGS) is None
    assert _tier_endpoint(ModelTier.PLANNING, {}, {}, {}) is None


def test_per_tier_settings_take_precedence_over_the_legacy_fields() -> None:
    tiers = {
        ModelTier.PLANNING.value: {
            "base_url": "https://planner.invalid/v1",
            "model_name": "planner",
        }
    }
    endpoint = _tier_endpoint(ModelTier.PLANNING, tiers, {}, LEGACY_SETTINGS)
    assert endpoint is not None
    assert endpoint.base_url == "https://planner.invalid/v1"


def test_legacy_fields_must_be_configured_together() -> None:
    partial = {"review_model_base_url": "https://legacy.invalid/v1"}
    try:
        _tier_endpoint(ModelTier.REVIEW, {}, {}, partial)
    except RuntimeError as error:
        assert "must be configured together" in str(error)
    else:  # pragma: no cover - the guard must reject a half-configured endpoint
        raise AssertionError("a half-configured legacy model must be rejected")
