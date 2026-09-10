"""ADR-021 audit-plan completeness and coverage gates."""
from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Iterable


@dataclass(frozen=True, slots=True)
class AuditBaseline:
    name: str
    required: bool = True


@dataclass(frozen=True, slots=True)
class AuditPlan:
    baselines: tuple[AuditBaseline, ...]
    completed: frozenset[str]

    def missing_required(self) -> tuple[str, ...]:
        return tuple(sorted(item.name for item in self.baselines if item.required and item.name not in self.completed))

    def coverage(self) -> float:
        required = [item for item in self.baselines if item.required]
        return 1.0 if not required else sum(item.name in self.completed for item in required) / len(required)

    def allows_no_findings(self) -> bool:
        return not self.missing_required()


def build_baseline_plan(*names: str) -> AuditPlan:
    """Build a deterministic plan, rejecting empty or duplicate baseline names."""
    normalized = tuple(sorted({name.strip() for name in names if name.strip()}))
    if not normalized or len(normalized) != len([name.strip() for name in names if name.strip()]):
        raise ValueError("audit plan requires unique non-empty baselines")
    return AuditPlan(tuple(AuditBaseline(name) for name in normalized), frozenset())


def complete_baselines(plan: AuditPlan, completed: Iterable[str]) -> AuditPlan:
    known = {item.name for item in plan.baselines}
    selected = frozenset(name for name in completed if name in known)
    return AuditPlan(plan.baselines, selected)
