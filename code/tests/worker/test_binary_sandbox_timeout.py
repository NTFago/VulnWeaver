"""Binary sandbox client timeout derivation from deployment settings."""

from __future__ import annotations

import pytest
from vulnweaver_analysis_worker.main import _binary_client_timeout, _binary_limits
from vulnweaver_domain import resolve_deployment_config


def _config(settings: dict[str, object], environ: dict[str, str] | None = None):
    return resolve_deployment_config(settings, environ or {})


def test_binary_client_timeout_defaults_to_command_timeout_plus_margin() -> None:
    # No settings, no env: the package default (1800s) plus a 60s margin.
    assert _binary_client_timeout(_config({})) == 1860.0
    assert _binary_limits(_config({})).command_timeout_seconds == 1800.0


def test_binary_client_timeout_follows_configured_command_timeout() -> None:
    config = _config({"binary_command_timeout_seconds": 3600})
    assert _binary_limits(config).command_timeout_seconds == 3600.0
    assert _binary_client_timeout(config) == 3660.0


def test_binary_client_timeout_keeps_the_larger_runner_timeout() -> None:
    config = _config(
        {"sandbox_runner_timeout_seconds": 7200, "binary_command_timeout_seconds": 600}
    )
    assert _binary_client_timeout(config) == 7200.0


def test_binary_client_timeout_reads_environment_fallbacks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SANDBOX_RUNNER_TIMEOUT_SECONDS", "300")
    monkeypatch.setenv("BINARY_COMMAND_TIMEOUT_SECONDS", "900")
    config = _config({}, {"BINARY_COMMAND_TIMEOUT_SECONDS": "900"})
    assert _binary_client_timeout(config) == 960.0
