"""Policy evaluation for structured ActionPlans."""

from __future__ import annotations

import copy
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol, cast
from urllib.parse import urlparse

from jsonschema import Draft202012Validator
from vulnweaver_contracts import (
    ActionPlan,
    ArtifactKind,
    JsonObject,
    JsonValue,
    NetworkAccess,
    PermissionMode,
    SchemaVersion,
    ToolSpec,
    validate_contract,
)

from vulnweaver_tool_runtime.errors import (
    PolicyPermissionRequired,
    PolicyRejected,
    ToolNotFound,
)
from vulnweaver_tool_runtime.registry import ToolRegistry


class PolicyDecisionStatus(StrEnum):
    APPROVED = "approved"
    WAITING_PERMISSION = "waiting_permission"
    DENIED = "denied"


@dataclass(frozen=True, slots=True)
class PolicyContext:
    """Facts supplied by the project/task boundary, never by model output.

    Compute-resource budgets are deliberately absent: tool scheduling is no
    longer gated on CPU/memory/disk/token quotas. Isolation and permission
    facts remain because those are security boundaries, not resource limits.
    """

    artifact_kinds: Mapping[str, ArtifactKind | str]
    permission_mode: PermissionMode
    allowed_network_hosts: frozenset[str] = frozenset()
    granted_approvals: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class PolicyViolation:
    code: str
    message: str
    step_id: str
    details: Mapping[str, object] = field(
        default_factory=lambda: cast(dict[str, object], {})
    )


@dataclass(frozen=True, slots=True)
class ScheduledToolCall:
    """A structured execution request; it intentionally contains no shell command."""

    step_id: str
    tool: ToolSpec
    input_refs: tuple[str, ...]
    arguments: JsonObject
    task_id: str
    plan_id: str


@dataclass(frozen=True, slots=True)
class PolicyAuditRecord:
    sequence: int
    plan_id: str
    task_id: str
    step_id: str
    tool_name: str
    tool_version: str
    decision: PolicyDecisionStatus
    reason_codes: tuple[str, ...]
    created_at: str


class PolicyAuditLog(Protocol):
    def append(self, record: PolicyAuditRecord) -> None: ...

    def list(self) -> tuple[PolicyAuditRecord, ...]: ...


class InMemoryPolicyAuditLog:
    """Small deterministic sink used by the MVP and replaceable by persistence later."""

    def __init__(self) -> None:
        self._records: list[PolicyAuditRecord] = []

    def append(self, record: PolicyAuditRecord) -> None:
        self._records.append(record)

    def list(self) -> tuple[PolicyAuditRecord, ...]:
        return tuple(self._records)

    def for_plan(self, plan_id: str) -> tuple[PolicyAuditRecord, ...]:
        return tuple(record for record in self._records if record.plan_id == plan_id)


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    status: PolicyDecisionStatus
    calls: tuple[ScheduledToolCall, ...]
    violations: tuple[PolicyViolation, ...]
    audit_records: tuple[PolicyAuditRecord, ...]

    @property
    def allowed(self) -> bool:
        return self.status is PolicyDecisionStatus.APPROVED

    @property
    def reason_codes(self) -> tuple[str, ...]:
        return tuple(violation.code for violation in self.violations)


class PolicyEngine:
    def __init__(
        self,
        registry: ToolRegistry,
        *,
        audit_log: PolicyAuditLog | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._registry = registry
        self._audit_log = audit_log or InMemoryPolicyAuditLog()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._audit_sequence = 0

    @property
    def audit_log(self) -> PolicyAuditLog:
        return self._audit_log

    def evaluate(self, plan: Mapping[str, object], context: PolicyContext) -> PolicyDecision:
        action_plan = _validated_plan(plan)
        violations: list[PolicyViolation] = []
        calls: list[ScheduledToolCall] = []
        records: list[PolicyAuditRecord] = []
        seen_steps: set[str] = set()
        waiting_for_permission = False

        for raw_step in action_plan["steps"]:
            step = cast(Mapping[str, object], raw_step)
            step_id = str(step["step_id"])
            tool_name = str(step["tool_name"])
            tool_version = str(step["tool_version"])
            step_violations: list[PolicyViolation] = []
            if step_id in seen_steps:
                step_violations.append(
                    _violation("duplicate_step_id", "ActionPlan step IDs must be unique", step_id)
                )
            seen_steps.add(step_id)
            try:
                spec = self._registry.resolve(tool_name, tool_version)
            except ToolNotFound:
                spec = None
                step_violations.append(
                    _violation(
                        "tool_not_registered",
                        "the exact tool name and version are not registered",
                        step_id,
                        name=tool_name,
                        version=tool_version,
                    )
                )

            if spec is not None:
                step_violations.extend(_check_step(spec, step, context))
                if not step_violations and _needs_permission(spec, context):
                    waiting_for_permission = True

            violations.extend(step_violations)
            reasons = tuple(item.code for item in step_violations)
            if spec is not None and not reasons and _needs_permission(spec, context):
                reasons = ("approval_required",)
            record = self._record(
                action_plan,
                step_id,
                tool_name,
                tool_version,
                PolicyDecisionStatus.DENIED
                if step_violations
                else (
                    PolicyDecisionStatus.WAITING_PERMISSION
                    if spec is not None and _needs_permission(spec, context)
                    else PolicyDecisionStatus.APPROVED
                ),
                reasons,
            )
            records.append(record)
            if spec is not None and not step_violations and not _needs_permission(spec, context):
                calls.append(
                    ScheduledToolCall(
                        step_id=step_id,
                        tool=copy.deepcopy(spec),
                        input_refs=tuple(cast(Sequence[str], step["input_refs"])),
                        arguments=copy.deepcopy(cast(JsonObject, step["arguments"])),
                        task_id=action_plan["task_id"],
                        plan_id=action_plan["id"],
                    )
                )

        if violations:
            status = PolicyDecisionStatus.DENIED
        elif waiting_for_permission:
            status = PolicyDecisionStatus.WAITING_PERMISSION
        else:
            status = PolicyDecisionStatus.APPROVED
        return PolicyDecision(status, tuple(calls), tuple(violations), tuple(records))

    def authorize(self, plan: Mapping[str, object], context: PolicyContext) -> PolicyDecision:
        decision = self.evaluate(plan, context)
        if decision.status is PolicyDecisionStatus.WAITING_PERMISSION:
            raise PolicyPermissionRequired(
                "tool execution requires an explicit project permission decision",
                details={"plan_id": str(plan.get("id", "")), "reason": "approval_required"},
            )
        if not decision.allowed:
            raise PolicyRejected(
                "ActionPlan was rejected by the Policy Engine",
                details={"reason_codes": list(decision.reason_codes)},
            )
        return decision

    def _record(
        self,
        plan: ActionPlan,
        step_id: str,
        tool_name: str,
        tool_version: str,
        decision: PolicyDecisionStatus,
        reasons: tuple[str, ...],
    ) -> PolicyAuditRecord:
        self._audit_sequence += 1
        record = PolicyAuditRecord(
            sequence=self._audit_sequence,
            plan_id=plan["id"],
            task_id=plan["task_id"],
            step_id=step_id,
            tool_name=tool_name,
            tool_version=tool_version,
            decision=decision,
            reason_codes=reasons,
            created_at=_timestamp(self._clock()),
        )
        self._audit_log.append(record)
        return record


def _validated_plan(value: Mapping[str, object]) -> ActionPlan:
    candidate = cast(ActionPlan, dict(value))
    validate_contract("ActionPlan", candidate)
    if candidate["schema_version"] != SchemaVersion.VALUE_1_0_0:
        raise PolicyRejected("unsupported ActionPlan schema version")
    return candidate


def _check_step(
    spec: ToolSpec, step: Mapping[str, object], context: PolicyContext
) -> list[PolicyViolation]:
    step_id = str(step["step_id"])
    violations: list[PolicyViolation] = []
    arguments = cast(JsonObject, step["arguments"])
    validator = Draft202012Validator(spec["command_schema"])
    iter_errors = cast(
        Callable[[object], Iterable[object]],
        validator.iter_errors,  # pyright: ignore[reportUnknownMemberType]
    )
    errors = iter_errors(arguments)
    for error in sorted(errors, key=str):
        violations.append(
            _violation(
                "invalid_tool_arguments",
                str(getattr(error, "message", error)),
                step_id,
                path=".".join(str(part) for part in getattr(error, "absolute_path", ())),
            )
        )
    violations.extend(_check_forbidden_arguments(arguments, step_id))
    violations.extend(_check_paths(arguments, step_id))

    kinds = context.artifact_kinds
    for ref in cast(Iterable[str], step["input_refs"]):
        kind = kinds.get(ref)
        if kind is None:
            violations.append(
                _violation(
                    "unknown_input_ref",
                    "input reference is not registered",
                    step_id,
                    ref=ref,
                )
            )
        elif ArtifactKind(kind) not in spec["accepted_artifacts"]:
            violations.append(
                _violation(
                    "artifact_kind_not_accepted",
                    "tool does not accept this input artifact kind",
                    step_id,
                    ref=ref,
                    artifact_kind=str(kind),
                )
            )

    violations.extend(_check_network(spec, arguments, context, step_id))
    return violations


def _check_network(
    spec: ToolSpec,
    arguments: JsonObject,
    context: PolicyContext,
    step_id: str,
) -> list[PolicyViolation]:
    requested = _network_hosts(arguments)
    if not requested:
        return []
    policy = spec["network_policy"]
    if policy["access"] is NetworkAccess.NONE:
        return [_violation("network_not_allowed", "tool has no network capability", step_id)]
    allowed = set(policy["allowed_hosts"]) & set(context.allowed_network_hosts)
    unauthorized = sorted(set(requested) - allowed)
    if unauthorized:
        return [
            _violation(
                "network_host_not_allowlisted",
                "requested network host is outside both tool and project allowlists",
                step_id,
                hosts=unauthorized,
            )
        ]
    return []


def _network_hosts(arguments: JsonObject) -> list[str]:
    result: list[str] = []
    for key in ("network_hosts", "hosts", "allowed_hosts"):
        value = arguments.get(key)
        if isinstance(value, str):
            result.append(_host_from_value(value))
        elif isinstance(value, list) and all(isinstance(item, str) for item in value):
            result.extend(_host_from_value(item) for item in cast(list[str], value))
    return result


def _host_from_value(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"//{value}")
    return (parsed.hostname or value).lower().rstrip(".")


_FORBIDDEN_KEYS = {
    "command",
    "cmd",
    "shell",
    "argv",
    "container_args",
    "docker_args",
    "host_path",
    "host_paths",
    "privileged",
    "cap_add",
    "capabilities",
    "network_mode",
}


def _check_forbidden_arguments(
    value: JsonValue, step_id: str, path: str = ""
) -> list[PolicyViolation]:
    violations: list[PolicyViolation] = []
    if isinstance(value, Mapping):
        for key, nested in value.items():
            name = str(key).lower()
            current_path = f"{path}.{name}" if path else name
            if name in _FORBIDDEN_KEYS:
                violations.append(
                    _violation(
                        "forbidden_argument",
                        "arbitrary command, container or privilege arguments are not accepted",
                        step_id,
                        path=current_path,
                    )
                )
            violations.extend(_check_forbidden_arguments(nested, step_id, current_path))
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            violations.extend(_check_forbidden_arguments(nested, step_id, f"{path}[{index}]"))
    return violations


_WINDOWS_ABSOLUTE = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\)")


def _check_paths(value: JsonValue, step_id: str, path: str = "") -> list[PolicyViolation]:
    violations: list[PolicyViolation] = []
    if isinstance(value, str):
        segments = re.split(r"[\\/]", value)
        if value.startswith(("/", "\\")) or _WINDOWS_ABSOLUTE.match(value) or ".." in segments:
            violations.append(
                _violation(
                    "host_path_or_traversal",
                    "absolute host paths and parent traversal are forbidden",
                    step_id,
                    path=path,
                )
            )
    elif isinstance(value, Mapping):
        for key, nested in value.items():
            current_path = f"{path}.{key}" if path else str(key)
            violations.extend(_check_paths(nested, step_id, current_path))
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            violations.extend(_check_paths(nested, step_id, f"{path}[{index}]"))
    return violations


def _needs_permission(spec: ToolSpec | None, context: PolicyContext) -> bool:
    if spec is None or not spec["approval_required"]:
        return False
    if context.permission_mode is PermissionMode.FULL_ACCESS:
        return False
    approval_key = f"{spec['name']}@{spec['version']}"
    return (
        approval_key not in context.granted_approvals
        and spec["name"] not in context.granted_approvals
    )


def _violation(code: str, message: str, step_id: str, **details: object) -> PolicyViolation:
    return PolicyViolation(code, message, step_id, details)


def _timestamp(value: object) -> str:
    if not isinstance(value, datetime):
        raise TypeError("policy clock must return datetime")
    if value.tzinfo is None:
        raise ValueError("policy audit timestamps require timezone-aware datetime")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
