"""Resource-budget arithmetic shared by every tool-scheduling component."""

from __future__ import annotations

from vulnweaver_contracts import ResourceBudget

RESOURCE_BUDGET_KEYS: tuple[str, ...] = (
    "max_model_tokens",
    "cpu_millis",
    "memory_bytes",
    "disk_bytes",
    "max_tool_concurrency",
    "max_dynamic_runs",
    "timeout_seconds",
)


def bounded_resource_budget(outer: ResourceBudget, limits: ResourceBudget) -> ResourceBudget:
    """Clamp a budget to a ToolSpec's declared limits, taking the smaller value per field.

    The Policy Engine and the Sandbox Runner both refuse work whose budget exceeds the tool's
    limits, so a caller forwarding a project- or task-level budget must clamp it to the spec
    first instead of letting the request be rejected downstream.
    """

    return ResourceBudget(
        max_model_tokens=min(outer["max_model_tokens"], limits["max_model_tokens"]),
        cpu_millis=min(outer["cpu_millis"], limits["cpu_millis"]),
        memory_bytes=min(outer["memory_bytes"], limits["memory_bytes"]),
        disk_bytes=min(outer["disk_bytes"], limits["disk_bytes"]),
        max_tool_concurrency=min(
            outer["max_tool_concurrency"], limits["max_tool_concurrency"]
        ),
        max_dynamic_runs=min(outer["max_dynamic_runs"], limits["max_dynamic_runs"]),
        timeout_seconds=min(outer["timeout_seconds"], limits["timeout_seconds"]),
    )
