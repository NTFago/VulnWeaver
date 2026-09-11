from __future__ import annotations

from datetime import UTC, datetime

import pytest
from vulnweaver_contracts import ArtifactKind, PermissionMode
from vulnweaver_tool_runtime import (
    InMemoryPolicyAuditLog,
    PolicyContext,
    PolicyDecisionStatus,
    PolicyEngine,
    PolicyPermissionRequired,
    ToolNotFound,
    ToolRegistrationConflict,
    ToolRegistry,
    ToolSpecError,
    ToolSpecLoader,
)

NOW = datetime(2026, 9, 8, 8, 0, tzinfo=UTC)


def budget(**overrides: int) -> dict[str, int]:
    result = {
        "max_model_tokens": 10_000,
        "cpu_millis": 2_000,
        "memory_bytes": 128 * 1024 * 1024,
        "disk_bytes": 256 * 1024 * 1024,
        "max_tool_concurrency": 4,
        "max_dynamic_runs": 2,
        "timeout_seconds": 120,
    }
    result.update(overrides)
    return result


def spec(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "1.0.0",
        "name": "semgrep",
        "version": "1.0.0",
        "image_digest": "sha256:" + "a" * 64,
        "risk_level": "low",
        "accepted_artifacts": ["source_archive"],
        "command_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["ruleset"],
            "properties": {"ruleset": {"type": "string", "minLength": 1}},
        },
        "output_schema": {"type": "object"},
        "network_policy": {"access": "none", "allowed_hosts": []},
        "filesystem_policy": {
            "input_read_only": True,
            "isolated_output": True,
            "allow_host_paths": False,
        },
        "resource_limits": budget(),
        "approval_required": False,
        "timeout_seconds": 60,
        "retry_policy": {
            "max_attempts": 2,
            "backoff_seconds": 1,
            "retryable_failure_kinds": ["timeout", "environment"],
        },
    }
    value.update(overrides)
    return value


def plan(arguments: dict[str, object] | None = None, **step_overrides: object) -> dict[str, object]:
    step: dict[str, object] = {
        "step_id": "step:1",
        "tool_name": "semgrep",
        "tool_version": "1.0.0",
        "input_refs": ["version:1"],
        "arguments": arguments or {"ruleset": "safe-default"},
        "expected_output_types": ["sarif"],
        "reason": "scan the registered source",
    }
    step.update(step_overrides)
    return {
        "schema_version": "1.0.0",
        "id": "plan:1",
        "task_id": "task:1",
        "agent_run_id": "run:1",
        "steps": [step],
        "created_at": "2026-09-08T08:00:00Z",
    }


def context(**overrides: object) -> PolicyContext:
    value: dict[str, object] = {
        "artifact_kinds": {"version:1": ArtifactKind.SOURCE_ARCHIVE},
        "permission_mode": PermissionMode.REQUEST_PERMISSION,
    }
    value.update(overrides)
    return PolicyContext(**value)  # type: ignore[arg-type]


def test_registry_is_exact_versioned_and_idempotent() -> None:
    registry = ToolRegistry()
    registered = registry.register(spec())
    assert registered["name"] == "semgrep"
    assert registry.resolve("semgrep", "1.0.0")["version"] == "1.0.0"
    registry.register(spec())
    assert len(registry) == 1
    with pytest.raises(ToolRegistrationConflict):
        registry.register(spec(version="1.0.0", timeout_seconds=30))
    with pytest.raises(ToolNotFound, match="exact tool"):
        registry.resolve("semgrep", "2.0.0")


def test_loader_accepts_single_and_collection_documents() -> None:
    assert ToolSpecLoader.from_document(spec())[0]["name"] == "semgrep"
    assert len(ToolSpecLoader.from_document([spec(), spec(name="cppcheck")])) == 2
    with pytest.raises(ToolSpecError, match="object or an array"):
        ToolSpecLoader.from_document("not-a-spec")
    with pytest.raises(ToolSpecError, match="non-object"):
        ToolSpecLoader.from_document([spec(), "not-a-spec"])


def test_policy_approves_structured_safe_call_and_records_audit() -> None:
    audit = InMemoryPolicyAuditLog()
    decision = PolicyEngine(ToolRegistry([spec()]), audit_log=audit, clock=lambda: NOW).evaluate(
        plan(), context()
    )
    assert decision.status is PolicyDecisionStatus.APPROVED
    assert decision.allowed
    assert len(decision.calls) == 1
    assert decision.calls[0].arguments == {"ruleset": "safe-default"}
    assert decision.audit_records[0].created_at == "2026-09-08T08:00:00Z"
    assert audit.for_plan("plan:1") == decision.audit_records


def test_policy_denies_unknown_tool_and_unregistered_input() -> None:
    decision = PolicyEngine(ToolRegistry([spec()]), clock=lambda: NOW).evaluate(
        plan(tool_name="unknown"), context(artifact_kinds={"other": "source_archive"})
    )
    assert decision.status is PolicyDecisionStatus.DENIED
    assert decision.reason_codes == ("tool_not_registered",)
    unknown_input = PolicyEngine(ToolRegistry([spec()]), clock=lambda: NOW).evaluate(
        plan(), context(artifact_kinds={"other": "source_archive"})
    )
    assert unknown_input.reason_codes == ("unknown_input_ref",)


def test_policy_validates_arguments_and_rejects_forbidden_controls() -> None:
    engine = PolicyEngine(ToolRegistry([spec()]), clock=lambda: NOW)
    decision = engine.evaluate(plan({"ruleset": "safe", "command": "rm -rf /"}), context())
    assert decision.status is PolicyDecisionStatus.DENIED
    assert "invalid_tool_arguments" in decision.reason_codes
    assert "forbidden_argument" in decision.reason_codes


def test_policy_rejects_absolute_and_traversal_paths() -> None:
    engine = PolicyEngine(ToolRegistry([spec(command_schema={})]), clock=lambda: NOW)
    for value in ("/tmp/input", r"C:\\sample", "../outside"):
        decision = engine.evaluate(plan({"path": value}), context())
        assert "host_path_or_traversal" in decision.reason_codes


def test_policy_enforces_artifact_and_network_boundaries() -> None:
    network_spec = spec(
        name="dependency-fetcher",
        network_policy={"access": "allowlist", "allowed_hosts": ["pypi.org"]},
    )
    engine = PolicyEngine(ToolRegistry([network_spec]), clock=lambda: NOW)
    p = plan(
        {"ruleset": "safe", "network_hosts": ["evil.example"]},
        tool_name="dependency-fetcher",
        input_refs=["version:1"],
    )
    decision = engine.evaluate(
        p,
        context(
            artifact_kinds={"version:1": ArtifactKind.ELF},
            allowed_network_hosts=frozenset({"pypi.org", "evil.example"}),
        ),
    )
    assert decision.status is PolicyDecisionStatus.DENIED
    assert "artifact_kind_not_accepted" in decision.reason_codes
    assert "network_host_not_allowlisted" in decision.reason_codes


def test_request_permission_waits_but_full_access_only_skips_approval() -> None:
    approval_spec = spec(approval_required=True)
    engine = PolicyEngine(ToolRegistry([approval_spec]), clock=lambda: NOW)
    waiting = engine.evaluate(plan(), context())
    assert waiting.status is PolicyDecisionStatus.WAITING_PERMISSION
    assert not waiting.calls
    with pytest.raises(PolicyPermissionRequired):
        engine.authorize(plan(), context())

    approved = engine.authorize(
        plan(), context(permission_mode=PermissionMode.FULL_ACCESS)
    )
    assert approved.allowed

    still_denied = engine.evaluate(
        plan({"ruleset": "safe", "host_path": "/etc/passwd"}),
        context(permission_mode=PermissionMode.FULL_ACCESS),
    )
    assert still_denied.status is PolicyDecisionStatus.DENIED
    assert "forbidden_argument" in still_denied.reason_codes


def test_registry_snapshot_is_detached() -> None:
    registry = ToolRegistry([spec()])
    snapshot = registry.snapshot()
    snapshot[0]["name"] = "mutated"  # type: ignore[index]
    assert registry.resolve("semgrep", "1.0.0")["name"] == "semgrep"


def test_registry_digests_publish_every_registered_identity() -> None:
    registry = ToolRegistry(
        [
            spec(name="afl-casr", image_digest="sha256:" + "b" * 64),
            spec(name="proof-tool", image_digest="sha256:" + "c" * 64),
        ]
    )

    assert registry.digests() == {
        ("afl-casr", "1.0.0"): "sha256:" + "b" * 64,
        ("proof-tool", "1.0.0"): "sha256:" + "c" * 64,
    }


def test_registry_rejects_an_unpinned_tool_spec() -> None:
    # Digest pinning is a schema invariant, so it cannot be bypassed by a spec.
    with pytest.raises(ToolSpecError):
        ToolRegistry([spec(image_digest="")])
