"""Project resource budgets: inert bookkeeping resolved server-side.

Compute-resource gating was removed (ADR-025): budgets no longer bound CPU,
memory, disk, concurrency, dynamic runs, timeouts or model output. Every
project still carries a budget row because the public contract and the
database retain the field for traceability; the server fills it with an
effectively unbounded value and ignores client-supplied numbers.
"""

from __future__ import annotations

from vulnweaver_contracts import ResourceBudget

# Values are far above any plausible workload. max_model_tokens stays 0 because
# model callers treat 0 as "no output cap".
UNBOUNDED_RESOURCE_BUDGET: ResourceBudget = ResourceBudget(
    max_model_tokens=0,
    cpu_millis=1_000_000,
    memory_bytes=1 << 40,
    disk_bytes=1 << 40,
    max_tool_concurrency=1_024,
    max_dynamic_runs=1_000_000,
    timeout_seconds=600,
)


def resolve_project_budget() -> ResourceBudget:
    """Return the stored project budget: a constant, effectively unbounded row."""

    return UNBOUNDED_RESOURCE_BUDGET
