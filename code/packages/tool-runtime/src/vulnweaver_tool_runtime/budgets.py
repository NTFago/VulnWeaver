"""Resource-budget key names shared by every tool-scheduling component.

Budgets are inert bookkeeping since the removal of compute-resource gating
(ADR-025): nothing compares them against ToolSpec limits or clamps requests
to them. The key tuple remains because contracts and persistence still carry
the structure for traceability.
"""

from __future__ import annotations

RESOURCE_BUDGET_KEYS: tuple[str, ...] = (
    "max_model_tokens",
    "cpu_millis",
    "memory_bytes",
    "disk_bytes",
    "max_tool_concurrency",
    "max_dynamic_runs",
    "timeout_seconds",
)
