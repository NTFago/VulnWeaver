"""Merge deployment settings: product settings override environment defaults.

Resolution order for every knob: the installation-scoped product settings row
(managed from the web settings page), then process environment variables, then
the caller-provided fallback. Empty/zero/None settings values mean "not set"
and fall through to the next level so existing env-only deployments keep
working unchanged.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

Digest = str


def _digest_from_settings(value: object) -> Digest | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _digest_from_env(value: str | None) -> Digest | None:
    if value is not None and value.strip():
        return value.strip()
    return None


def _int_from_settings(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return None


def _int_from_env(value: str | None) -> int | None:
    if value is None or not value.strip():
        return None
    try:
        parsed = int(value.strip())
    except ValueError:
        return None
    return parsed if parsed > 0 else None


def _bool_from_env(value: str | None) -> bool | None:
    if value is None or not value.strip():
        return None
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True, slots=True)
class ResolvedDigests:
    binary_tools: Digest | None
    proof_tool: Digest | None
    afl_casr: Digest | None


@dataclass(frozen=True, slots=True)
class ResolvedResourceBudget:
    cpu_millis: int | None
    memory_bytes: int | None
    disk_bytes: int | None
    timeout_seconds: int | None


@dataclass(frozen=True, slots=True)
class ResolvedDeploymentConfig:
    """Effective deployment knobs after the settings > env > default merge."""

    digests: ResolvedDigests
    budgets: Mapping[str, ResolvedResourceBudget]
    fuzz_max_executions: int | None
    fuzz_max_duration_seconds: int | None
    fuzz_max_crashes: int | None
    sandbox_runner_timeout_seconds: int | None
    fuzz_runner_timeout_seconds: int | None
    angr_enabled: bool | None
    # Wall-clock bounds for the two agent loops.  A positive value wins; zero or
    # absent falls through to the environment and then to the built-in default,
    # which is how every other resolved knob behaves.
    audit_deadline_seconds: int | None = None
    reverse_planning_deadline_seconds: int | None = None


def resolve_deployment_config(
    settings: Mapping[str, object],
    environ: Mapping[str, str],
    *,
    defaults: ResolvedDeploymentConfig | None = None,
) -> ResolvedDeploymentConfig:
    """Merge one product-settings row with the process environment.

    ``settings`` is the raw ``product_settings.values`` mapping; missing or
    zero/empty values never override a configured environment variable.
    """

    base = defaults or ResolvedDeploymentConfig(
        digests=ResolvedDigests(None, None, None),
        budgets={},
        fuzz_max_executions=None,
        fuzz_max_duration_seconds=None,
        fuzz_max_crashes=None,
        sandbox_runner_timeout_seconds=None,
        fuzz_runner_timeout_seconds=None,
        angr_enabled=None,
    )
    settings_digests = _mapping(settings.get("tool_image_digests"))
    settings_budgets = _mapping(settings.get("sandbox_budgets"))
    settings_fuzz = _mapping(settings.get("fuzz_budgets"))
    settings_agent_loop = _mapping(settings.get("agent_loop_budgets"))

    digests = ResolvedDigests(
        binary_tools=_first(
            _digest_from_settings(settings_digests.get("binary_tools")),
            _digest_from_env(environ.get("BINARY_TOOLS_IMAGE_DIGEST")),
            base.digests.binary_tools,
        ),
        proof_tool=_first(
            _digest_from_settings(settings_digests.get("proof_tool")),
            _digest_from_env(environ.get("PROOF_IMAGE_DIGEST")),
            base.digests.proof_tool,
        ),
        afl_casr=_first(
            _digest_from_settings(settings_digests.get("afl_casr")),
            _digest_from_env(environ.get("AFL_CASR_IMAGE_DIGEST")),
            base.digests.afl_casr,
        ),
    )

    budget_env = {
        "afl": (
            "AFL_CPU_MILLIS",
            "AFL_MEMORY_BYTES",
            "AFL_DISK_BYTES",
            "AFL_TIMEOUT_SECONDS",
        ),
        "proof": (
            "PROOF_CPU_MILLIS",
            "PROOF_MEMORY_BYTES",
            "PROOF_DISK_BYTES",
            "PROOF_TIMEOUT_SECONDS",
        ),
        "binary": (
            "BINARY_CPU_MILLIS",
            "BINARY_MEMORY_BYTES",
            "BINARY_DISK_BYTES",
            "BINARY_TIMEOUT_SECONDS",
        ),
    }
    budgets: dict[str, ResolvedResourceBudget] = {}
    for name, (cpu_key, memory_key, disk_key, timeout_key) in budget_env.items():
        settings_budget = _mapping(settings_budgets.get(name))
        base_budget = base.budgets.get(name) or ResolvedResourceBudget(None, None, None, None)
        budgets[name] = ResolvedResourceBudget(
            cpu_millis=_first(
                _int_from_settings(settings_budget.get("cpu_millis")),
                _int_from_env(environ.get(cpu_key)),
                base_budget.cpu_millis,
            ),
            memory_bytes=_first(
                _int_from_settings(settings_budget.get("memory_bytes")),
                _int_from_env(environ.get(memory_key)),
                base_budget.memory_bytes,
            ),
            disk_bytes=_first(
                _int_from_settings(settings_budget.get("disk_bytes")),
                _int_from_env(environ.get(disk_key)),
                base_budget.disk_bytes,
            ),
            timeout_seconds=_first(
                _int_from_settings(settings_budget.get("timeout_seconds")),
                _int_from_env(environ.get(timeout_key)),
                base_budget.timeout_seconds,
            ),
        )

    angr_settings = settings.get("angr_enabled")
    return ResolvedDeploymentConfig(
        digests=digests,
        budgets=budgets,
        fuzz_max_executions=_first(
            _int_from_settings(settings_fuzz.get("max_executions")),
            _int_from_env(environ.get("AFL_MAX_EXECUTIONS")),
            base.fuzz_max_executions,
        ),
        fuzz_max_duration_seconds=_first(
            _int_from_settings(settings_fuzz.get("max_duration_seconds")),
            _int_from_env(environ.get("AFL_MAX_DURATION_SECONDS")),
            base.fuzz_max_duration_seconds,
        ),
        fuzz_max_crashes=_first(
            _int_from_settings(settings_fuzz.get("max_crashes")),
            _int_from_env(environ.get("AFL_MAX_CRASHES")),
            base.fuzz_max_crashes,
        ),
        sandbox_runner_timeout_seconds=_first(
            _int_from_settings(settings.get("sandbox_runner_timeout_seconds")),
            _int_from_env(environ.get("SANDBOX_RUNNER_TIMEOUT_SECONDS")),
            base.sandbox_runner_timeout_seconds,
        ),
        fuzz_runner_timeout_seconds=_first(
            _int_from_settings(settings.get("fuzz_runner_timeout_seconds")),
            _int_from_env(environ.get("FUZZ_RUNNER_TIMEOUT_SECONDS")),
            base.fuzz_runner_timeout_seconds,
        ),
        audit_deadline_seconds=_first(
            _int_from_settings(settings_agent_loop.get("audit_deadline_seconds")),
            _int_from_env(environ.get("AGENT_AUDIT_DEADLINE_SECONDS")),
            base.audit_deadline_seconds,
        ),
        reverse_planning_deadline_seconds=_first(
            _int_from_settings(settings_agent_loop.get("reverse_planning_deadline_seconds")),
            _int_from_env(environ.get("AGENT_REVERSE_PLANNING_DEADLINE_SECONDS")),
            base.reverse_planning_deadline_seconds,
        ),
        angr_enabled=_first(
            angr_settings if isinstance(angr_settings, bool) else None,
            _bool_from_env(environ.get("ANGR_ENABLED")),
            base.angr_enabled,
        ),
    )


def _mapping(value: object) -> Mapping[str, object]:
    return cast(Mapping[str, object], value) if isinstance(value, Mapping) else {}


def _first[T](primary: T | None, *fallbacks: object) -> T | None:
    """Return the first non-None candidate; fallbacks share primary's type slot."""

    for candidate in (primary, *fallbacks):
        if candidate is not None:
            return cast("T", candidate)
    return None
