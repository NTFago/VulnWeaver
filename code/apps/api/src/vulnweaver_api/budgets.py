"""Project resource budgets derived from the registered ToolSpecs.

The Policy Engine refuses an initial analysis step whose ToolSpec limit exceeds the project
budget, so a project created with a budget below the shipped specs fails every task without
the operator being able to tell why. Resolving the default here, and rejecting an explicitly
requested budget below the floor, turns that late task failure into an actionable error at
project creation.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from vulnweaver_contracts import ResourceBudget
from vulnweaver_tool_runtime import ToolRegistry

from vulnweaver_api.errors import ApiInputError

RESOURCE_BUDGET_KEYS: tuple[str, ...] = (
    "max_model_tokens",
    "cpu_millis",
    "memory_bytes",
    "disk_bytes",
    "max_tool_concurrency",
    "max_dynamic_runs",
    "timeout_seconds",
)

# Dynamic runs are registered by the sandbox runner rather than by deploy/tool-specs, so no
# shipped spec declares them. Fuzz and proof jobs are gated by the project-level exploit flag,
# so the default budget must leave at least one run available or those jobs cannot start.
MINIMUM_DYNAMIC_RUNS = 1


def minimum_resource_budget(registry: ToolRegistry | None) -> ResourceBudget | None:
    """Return the smallest budget that can run every registered tool.

    Returns ``None`` when the deployment configures no tool spec directory, in which case the
    budget cannot be checked and must be supplied by the caller.
    """

    if registry is None:
        return None
    limits: dict[str, int] = dict.fromkeys(RESOURCE_BUDGET_KEYS, 0)
    for spec in registry.snapshot():
        spec_limits = cast(Mapping[str, int], spec["resource_limits"])
        for key in RESOURCE_BUDGET_KEYS:
            limits[key] = max(limits[key], int(spec_limits[key]))
    return cast(ResourceBudget, limits)


def resolve_project_budget(
    registry: ToolRegistry | None,
    requested: ResourceBudget | None,
    *,
    exploit_validation_enabled: bool,
) -> ResourceBudget:
    """Return the effective project budget, rejecting one that cannot run the shipped tools."""

    floor = minimum_resource_budget(registry)
    if requested is None:
        if floor is None:
            raise ApiInputError(
                "resource_budget_required",
                "a resource budget is required when the deployment configures no tool specs",
                "resource_budget",
            )
        resolved = cast(
            ResourceBudget,
            {**floor, "max_dynamic_runs": max(floor["max_dynamic_runs"], MINIMUM_DYNAMIC_RUNS)},
        )
    else:
        resolved = requested
        if floor is not None:
            _reject_below_floor(requested, floor)
    if exploit_validation_enabled and resolved["max_dynamic_runs"] < MINIMUM_DYNAMIC_RUNS:
        raise ApiInputError(
            "resource_budget_blocks_dynamic_runs",
            "exploit validation is enabled but the resource budget allows no dynamic runs",
            "resource_budget.max_dynamic_runs",
        )
    return resolved


def _reject_below_floor(requested: ResourceBudget, floor: ResourceBudget) -> None:
    deficits = [
        f"{key} {requested[key]} < {floor[key]}"
        for key in RESOURCE_BUDGET_KEYS
        if requested[key] < floor[key]
    ]
    if deficits:
        raise ApiInputError(
            "resource_budget_below_tool_requirements",
            "resource budget is below what the registered tools require: " + ", ".join(deficits),
            "resource_budget",
        )
