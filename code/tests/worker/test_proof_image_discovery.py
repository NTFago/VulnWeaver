"""Proof-tool image digest resolution for the dynamic-verification schedulers."""

from __future__ import annotations

import asyncio

import pytest
from vulnweaver_analysis_worker.main import (
    _auto_exploit_scheduler,
    _poc_scheduler,
    _proof_tool_image_digest,
)
from vulnweaver_domain import resolve_deployment_config

DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64


def _config(settings: dict[str, object], environ: dict[str, str] | None = None):
    return resolve_deployment_config(settings, environ or {})


def _resolved(settings: dict[str, object], environ: dict[str, str] | None = None) -> str | None:
    return asyncio.run(_proof_tool_image_digest(_config(settings, environ)))


class _FakeRunnerClient:
    def __init__(self, digest: str | None) -> None:
        self.digest = digest
        self.requests: list[tuple[str, str]] = []

    async def tool_digest(self, tool_name: str, tool_version: str) -> str | None:
        self.requests.append((tool_name, tool_version))
        return self.digest


def test_pinned_settings_digest_skips_discovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SANDBOX_RUNNER_URL", "http://sandbox-runner:8080")

    def _fail(*_args: object) -> object:
        raise AssertionError("pinned digest must not query the runner")

    monkeypatch.setattr("vulnweaver_analysis_worker.main._sandbox_client", _fail)
    assert _resolved({"tool_image_digests": {"proof_tool": DIGEST}}) == DIGEST


def test_unpinned_digest_discovers_from_runner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SANDBOX_RUNNER_URL", "http://sandbox-runner:8080")
    client = _FakeRunnerClient(DIGEST)
    monkeypatch.setattr("vulnweaver_analysis_worker.main._sandbox_client", lambda *_: client)
    assert _resolved({}) == DIGEST
    # The discovered identity must be the same tool the proof executor runs.
    assert client.requests == [("proof-tool", "1.0.0")]


def test_unpinned_digest_without_runner_stays_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SANDBOX_RUNNER_URL", raising=False)
    assert _resolved({}) is None


def test_runner_without_registered_proof_tool_stays_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SANDBOX_RUNNER_URL", "http://sandbox-runner:8080")
    client = _FakeRunnerClient(None)
    monkeypatch.setattr("vulnweaver_analysis_worker.main._sandbox_client", lambda *_: client)
    assert _resolved({}) is None


def test_environment_digests_still_resolve_without_discovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SANDBOX_RUNNER_URL", raising=False)
    assert _resolved({}, {"PROOF_IMAGE_DIGEST": DIGEST}) == DIGEST
    # Legacy alias honoured for deployments predating the settings page; the
    # scheduler builders read it from the process environment like before.
    monkeypatch.setenv("PROOF_TOOL_IMAGE_DIGEST", OTHER_DIGEST)
    assert _resolved({}) == OTHER_DIGEST


def test_schedulers_gate_on_the_resolved_digest() -> None:
    assert _poc_scheduler(None, None) is None
    assert _auto_exploit_scheduler(None, None) is None
    poc = _poc_scheduler(object(), DIGEST)
    assert poc is not None and poc._image_digest == DIGEST
    exploit = _auto_exploit_scheduler(object(), DIGEST)
    assert exploit is not None and exploit._image_digest == DIGEST
