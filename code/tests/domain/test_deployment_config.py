"""Merge-order tests for resolve_deployment_config."""

from __future__ import annotations

from vulnweaver_domain import resolve_deployment_config


def test_settings_override_environment() -> None:
    config = resolve_deployment_config(
        {
            "tool_image_digests": {"binary_tools": "sha256:" + "a" * 64},
            "sandbox_budgets": {"afl": {"cpu_millis": 5000, "timeout_seconds": 90}},
        },
        {
            "BINARY_TOOLS_IMAGE_DIGEST": "sha256:" + "b" * 64,
            "AFL_CPU_MILLIS": "1000",
        },
    )
    assert config.digests.binary_tools == "sha256:" + "a" * 64
    assert config.budgets["afl"].cpu_millis == 5000
    # settings only set two of four AFL fields; env fills the rest
    assert config.budgets["afl"].timeout_seconds == 90
    assert config.budgets["afl"].memory_bytes is None


def test_environment_used_when_settings_empty() -> None:
    config = resolve_deployment_config(
        {"tool_image_digests": {"binary_tools": None, "proof_tool": ""}},
        {
            "BINARY_TOOLS_IMAGE_DIGEST": " sha256:" + "c" * 64 + " ",
            "AFL_MAX_EXECUTIONS": "500",
            "ANGR_ENABLED": "true",
        },
    )
    assert config.digests.binary_tools == "sha256:" + "c" * 64
    assert config.digests.proof_tool is None
    assert config.fuzz_max_executions == 500
    assert config.angr_enabled is True


def test_zero_and_missing_values_fall_through() -> None:
    config = resolve_deployment_config(
        {
            "tool_image_digests": {},
            "sandbox_budgets": {"proof": {"cpu_millis": 0, "memory_bytes": 1024}},
            "fuzz_budgets": {"max_executions": 0},
            "sandbox_runner_timeout_seconds": 0,
            "angr_enabled": False,
        },
        {"PROOF_CPU_MILLIS": "7000"},
    )
    assert config.digests.binary_tools is None
    # zero means "not set" and falls to env
    assert config.budgets["proof"].cpu_millis == 7000
    # explicit False is a valid boolean setting, not a fall-through
    assert config.angr_enabled is False
    assert config.budgets["proof"].memory_bytes == 1024
    assert config.fuzz_max_executions is None


def test_invalid_environment_numbers_ignored() -> None:
    config = resolve_deployment_config(
        {},
        {"AFL_MEMORY_BYTES": "not-a-number", "AFL_MAX_CRASHES": "-5"},
    )
    assert config.budgets["afl"].memory_bytes is None
    assert config.fuzz_max_crashes is None


def test_malformed_settings_shapes_ignored() -> None:
    config = resolve_deployment_config(
        {
            "tool_image_digests": "not-a-mapping",
            "sandbox_budgets": {"afl": "also-not-a-mapping"},
            "fuzz_budgets": None,
        },
        {},
    )
    assert config.digests.binary_tools is None
    assert config.budgets["afl"].cpu_millis is None
    assert config.fuzz_max_executions is None


def test_proof_and_binary_env_pairs_resolved() -> None:
    config = resolve_deployment_config(
        {},
        {
            "PROOF_IMAGE_DIGEST": "sha256:" + "d" * 64,
            "BINARY_TIMEOUT_SECONDS": "120",
            "FUZZ_RUNNER_TIMEOUT_SECONDS": "900",
            "SANDBOX_RUNNER_TIMEOUT_SECONDS": "45",
        },
    )
    assert config.digests.proof_tool == "sha256:" + "d" * 64
    assert config.budgets["binary"].timeout_seconds == 120
    assert config.fuzz_runner_timeout_seconds == 900
    assert config.sandbox_runner_timeout_seconds == 45


def test_agent_loop_deadlines_resolve_settings_then_environment() -> None:
    from_settings = resolve_deployment_config(
        {"agent_loop_budgets": {"audit_deadline_seconds": 1800}},
        {
            "AGENT_AUDIT_DEADLINE_SECONDS": "60",
            "AGENT_REVERSE_PLANNING_DEADLINE_SECONDS": "900",
        },
    )
    # The setting wins for the field it names; the untouched one takes the env.
    assert from_settings.audit_deadline_seconds == 1800
    assert from_settings.reverse_planning_deadline_seconds == 900


def test_agent_loop_deadlines_fall_through_when_unset() -> None:
    config = resolve_deployment_config(
        # Zero is "unset" here, as it is for every other resolved knob, so the
        # environment still gets its say.
        {"agent_loop_budgets": {"audit_deadline_seconds": 0}},
        {"AGENT_AUDIT_DEADLINE_SECONDS": "120"},
    )
    assert config.audit_deadline_seconds == 120


def test_agent_loop_deadlines_default_to_none() -> None:
    config = resolve_deployment_config({}, {})
    assert config.audit_deadline_seconds is None
    assert config.reverse_planning_deadline_seconds is None
