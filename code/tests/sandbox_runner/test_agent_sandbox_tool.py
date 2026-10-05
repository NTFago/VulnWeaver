"""Agent sandbox command tool: profile construction and executor gating (ADR-038)."""

from __future__ import annotations

import asyncio

import pytest
from vulnweaver_contracts import ArtifactKind
from vulnweaver_sandbox_runner_service.agent_sandbox import (
    _MAX_COMMAND_CHARS,
    agent_sandbox_command_profile,
    agent_sandbox_tool_spec,
)


def _profile() -> object:
    return agent_sandbox_command_profile(
        "vulnweaver-proof:fixed", "sha256:" + "a" * 64
    )


def test_tool_spec_satisfies_the_public_contract() -> None:
    spec = agent_sandbox_tool_spec("sha256:" + "a" * 64, _budget())
    assert spec["name"] == "agent-sandbox"
    assert spec["network_policy"]["access"] == "none"
    assert spec["filesystem_policy"]["input_read_only"] is True
    assert spec["filesystem_policy"]["allow_host_paths"] is False
    assert spec["approval_required"] is False


def test_profile_builds_a_bounded_shell_invocation_in_the_workdir() -> None:
    profile = agent_sandbox_command_profile(
        "vulnweaver-proof:fixed", "sha256:" + "a" * 64
    )
    argv = profile.build_argv({"command": "python3 -V"}, None, None)
    assert argv[0] == "/bin/sh"
    assert argv[1] == "-c"
    assert argv[2].startswith("cd /work && ")
    assert argv[2].endswith("python3 -V")


def test_profile_rejects_empty_oversized_and_control_char_commands() -> None:
    profile = agent_sandbox_command_profile(
        "vulnweaver-proof:fixed", "sha256:" + "a" * 64
    )
    with pytest.raises(ValueError):
        profile.build_argv({"command": ""}, None, None)
    with pytest.raises(ValueError):
        profile.build_argv({"command": "x" * (_MAX_COMMAND_CHARS + 1)}, None, None)
    with pytest.raises(ValueError):
        profile.build_argv({"command": "echo a\necho b"}, None, None)
    with pytest.raises(ValueError):
        profile.build_argv({}, None, None)


def _budget() -> dict[str, object]:
    return {
        "max_model_tokens": 0,
        "cpu_millis": 4000,
        "memory_bytes": 1024 * 1024 * 1024,
        "disk_bytes": 1024 * 1024 * 1024,
        "max_tool_concurrency": 1,
        "max_dynamic_runs": 1,
        "timeout_seconds": 600,
    }


class _FakeCommandRunner:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    async def __call__(self, *, version_id: str, artifact_kind: ArtifactKind, command: str):
        self.calls.append(
            {"version_id": version_id, "artifact_kind": artifact_kind, "command": command}
        )
        return {"status": "succeeded", "exit_code": 0, "stdout": "out", "stderr": ""}


def _executor(
    *,
    command_runner: object | None = object(),
    dynamic_enabled: bool = True,
    indexed_versions: tuple[str, ...] = ("artifact-version:sample",),
):
    from vulnweaver_orchestrator.audit_tools import AuditStepExecutor

    class _StubWorkspace:
        def has_version(self, version_id: str) -> bool:
            return version_id in indexed_versions

        def version_kind(self, version_id: str) -> ArtifactKind:
            return ArtifactKind.SOURCE_ARCHIVE

    executor = AuditStepExecutor(
        _StubWorkspace(),  # type: ignore[arg-type]
        command_runner=command_runner,  # type: ignore[arg-type]
        dynamic_verification_enabled=dynamic_enabled,
    )
    return executor


def _call(arguments: dict[str, object]) -> object:
    from vulnweaver_tool_runtime import ScheduledToolCall

    return ScheduledToolCall(
        step_id="s1",
        tool={
            "name": "sandbox-command",
            "version": "1.0.0",
            "image_digest": "sha256:" + "0" * 64,
        },
        input_refs=(),
        arguments=arguments,
        task_id="task:1",
        plan_id="plan:1",
    )


def test_executor_runs_an_anchored_command_and_counts_budget() -> None:
    runner = _FakeCommandRunner()
    executor = _executor(command_runner=runner)
    result = asyncio.run(
        executor.execute(
            _call(  # type: ignore[arg-type]
                {
                    "artifact_version_id": "artifact-version:sample",
                    "command": "python3 -V",
                }
            )
        )
    )
    assert result["executed"] is True
    assert result["commands"] == 1
    assert result["observation"]["status"] == "succeeded"
    assert len(runner.calls) == 1
    assert runner.calls[0]["artifact_kind"] == ArtifactKind.SOURCE_ARCHIVE


def test_executor_enforces_every_gate() -> None:
    arguments = {"artifact_version_id": "artifact-version:sample", "command": "id"}

    def _run(executor: object) -> dict[str, object]:
        return asyncio.run(
            executor.execute(_call(arguments))  # type: ignore[arg-type]
        )

    no_runner = _executor(command_runner=None)
    assert _run(no_runner)["reason_code"] == "sandbox_command.no_runner_configured"

    disabled = _executor(dynamic_enabled=False)
    assert (
        _run(disabled)["reason_code"] == "sandbox_command.dynamic_verification_disabled"
    )

    unanchored = _executor(indexed_versions=())
    assert _run(unanchored)["reason_code"] == "sandbox_command.unanchored_version"

    runner = _FakeCommandRunner()
    capped = _executor(command_runner=runner)
    for expected in range(1, 9):
        assert _run(capped)["commands"] == expected
    ninth = _run(capped)
    assert ninth["reason_code"] == "sandbox_command.budget_exhausted"
    assert len(runner.calls) == 8
