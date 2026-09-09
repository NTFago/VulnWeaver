"""Fixed-flag container runtime for Sandbox Runner."""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from vulnweaver_contracts import ResourceBudget


@dataclass(frozen=True, slots=True)
class RuntimeRequest:
    container_name: str
    label: str
    image_ref: str
    image_digest: str
    argv: tuple[str, ...]
    input_dir: Path
    output_dir: Path
    resource_budget: ResourceBudget
    timeout_seconds: int
    max_output_bytes: int


@dataclass(frozen=True, slots=True)
class RuntimeExecution:
    status: str
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    duration_millis: int
    cpu_millis: int
    memory_bytes: int


class SandboxRuntime(Protocol):
    async def run(
        self, request: RuntimeRequest, cancellation: asyncio.Event
    ) -> RuntimeExecution: ...

    async def cleanup(self, container_name: str) -> bool: ...

    async def list_owned(self, label: str) -> tuple[str, ...]: ...


class DockerCliRuntime:
    """Invoke Docker with an immutable, non-privileged argument profile."""

    def __init__(
        self,
        *,
        docker_executable: str = "docker",
        root: str | Path = "/var/lib/vulnweaver/sandbox",
        command_timeout_seconds: float = 15.0,
    ) -> None:
        if not 1 <= command_timeout_seconds <= 60:
            raise ValueError("Docker command timeout must be between 1 and 60 seconds")
        self._docker = docker_executable
        self._command_timeout_seconds = command_timeout_seconds
        self._root = Path(root).expanduser().resolve()
        self._root.mkdir(parents=True, exist_ok=True)

    async def run(self, request: RuntimeRequest, cancellation: asyncio.Event) -> RuntimeExecution:
        self._validate_request(request)
        started = time.monotonic()
        arguments = self._run_arguments(request)
        process = await asyncio.create_subprocess_exec(
            *arguments,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_runtime_environment(),
        )
        overflow = asyncio.Event()
        communicate = asyncio.create_task(_communicate(process, request.max_output_bytes, overflow))
        cancelled = asyncio.create_task(cancellation.wait())
        overflowed = asyncio.create_task(overflow.wait())
        status = "failed"
        try:
            done, _ = await asyncio.wait(
                {communicate, cancelled, overflowed},
                timeout=request.timeout_seconds,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if not done:
                await self._stop(request.container_name)
                await _finish_communication(communicate)
                status = "timed_out"
                stdout, stderr, exit_code = b"", b"", None
            elif cancelled in done and cancelled.result():
                await self._stop(request.container_name)
                await _finish_communication(communicate)
                status = "cancelled"
                stdout, stderr, exit_code = b"", b"", None
            elif overflowed in done and overflowed.result():
                await self._stop(request.container_name)
                await _finish_communication(communicate)
                status = "failed"
                stdout, stderr, exit_code = b"", b"", None
            else:
                try:
                    stdout, stderr, exit_code = await communicate
                except OutputLimitExceeded:
                    await self._stop(request.container_name)
                    status = "failed"
                    stdout, stderr, exit_code = b"", b"", None
                else:
                    status = "succeeded" if exit_code == 0 else "failed"
            cpu_millis, memory_bytes = await self._usage(request.container_name)
            return RuntimeExecution(
                status=status,
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                duration_millis=max(0, int((time.monotonic() - started) * 1000)),
                cpu_millis=cpu_millis,
                memory_bytes=memory_bytes,
            )
        finally:
            cancelled.cancel()
            overflowed.cancel()
            if not communicate.done():
                communicate.cancel()
            await asyncio.gather(cancelled, overflowed, communicate, return_exceptions=True)

    async def cleanup(self, container_name: str) -> bool:
        if not _safe_container_name(container_name):
            return False
        process = await asyncio.create_subprocess_exec(
            self._docker,
            "rm",
            "--force",
            container_name,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_runtime_environment(),
        )
        await _communicate_with_timeout(process, self._command_timeout_seconds)
        return process.returncode == 0

    async def list_owned(self, label: str) -> tuple[str, ...]:
        if not _safe_label(label):
            return ()
        process = await asyncio.create_subprocess_exec(
            self._docker,
            "ps",
            "--all",
            "--filter",
            f"label={label}",
            "--format",
            "{{.Names}}",
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_runtime_environment(),
        )
        stdout, _ = await _communicate_with_timeout(process, self._command_timeout_seconds)
        if process.returncode != 0:
            return ()
        return tuple(
            sorted(
                name
                for name in stdout.decode("utf-8", "replace").splitlines()
                if _safe_container_name(name)
            )
        )

    def build_arguments(self, request: RuntimeRequest) -> tuple[str, ...]:
        self.validate_request(request)
        return self._run_arguments(request)

    def validate_request(self, request: RuntimeRequest) -> None:
        self._validate_request(request)

    def _run_arguments(self, request: RuntimeRequest) -> tuple[str, ...]:
        cpus = max(0.001, request.resource_budget["cpu_millis"] / 1000)
        image = f"{request.image_ref}@{request.image_digest}"
        return (
            self._docker,
            "run",
            "--name",
            request.container_name,
            "--label",
            request.label,
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges=true",
            "--pids-limit",
            "128",
            "--memory",
            str(request.resource_budget["memory_bytes"]),
            "--cpus",
            f"{cpus:g}",
            "--tmpfs",
            f"/tmp:rw,noexec,nosuid,size={request.resource_budget['disk_bytes']}",
            "--mount",
            f"type=bind,src={request.input_dir},dst=/input,readonly",
            "--mount",
            f"type=bind,src={request.output_dir},dst=/output",
            "--user",
            "10001:10001",
            image,
            *request.argv,
        )

    def _validate_request(self, request: RuntimeRequest) -> None:
        if not _safe_container_name(request.container_name):
            raise ValueError("invalid sandbox container name")
        if not _safe_label(request.label):
            raise ValueError("invalid sandbox label")
        if not _safe_image_ref(request.image_ref):
            raise ValueError("invalid sandbox image reference")
        if re.fullmatch(r"sha256:[0-9a-f]{64}", request.image_digest) is None:
            raise ValueError("sandbox image must be digest pinned")
        if not request.argv or len(request.argv) > 64:
            raise ValueError("sandbox argv must contain between 1 and 64 arguments")
        if any(
            not item
            or len(item) > 4096
            or "\x00" in item
            or "\n" in item
            or "\r" in item
            for item in request.argv
        ):
            raise ValueError("sandbox argv contains an invalid argument")
        _assert_within(self._root, request.input_dir)
        _assert_within(self._root, request.output_dir)
        if request.timeout_seconds < 1 or request.max_output_bytes < 1:
            raise ValueError("sandbox limits must be positive")

    async def _stop(self, container_name: str) -> None:
        if not _safe_container_name(container_name):
            return
        process = await asyncio.create_subprocess_exec(
            self._docker,
            "stop",
            "--time",
            "5",
            container_name,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_runtime_environment(),
        )
        await _communicate_with_timeout(process, self._command_timeout_seconds)

    async def _usage(self, container_name: str) -> tuple[int, int]:
        if not _safe_container_name(container_name):
            return 0, 0
        process = await asyncio.create_subprocess_exec(
            self._docker,
            "stats",
            "--no-stream",
            "--format",
            "{{json .}}",
            container_name,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_runtime_environment(),
        )
        stdout, _ = await _communicate_with_timeout(process, self._command_timeout_seconds)
        if process.returncode != 0:
            return 0, 0
        try:
            payload = json.loads(stdout.decode("utf-8", "replace").splitlines()[0])
            cpu = _parse_cpu(payload.get("CPUPerc"))
            memory = _parse_memory(payload.get("MemUsage"))
            return cpu, memory
        except (IndexError, TypeError, ValueError, json.JSONDecodeError):
            return 0, 0


def _runtime_environment() -> dict[str, str]:
    return {"PATH": os.environ.get("PATH", ""), "LANG": "C", "LC_ALL": "C"}


async def _communicate_with_timeout(
    process: asyncio.subprocess.Process, timeout_seconds: float
) -> tuple[bytes, bytes]:
    communication = asyncio.create_task(process.communicate())
    try:
        return await asyncio.wait_for(asyncio.shield(communication), timeout_seconds)
    except (TimeoutError, asyncio.CancelledError):
        with suppress(ProcessLookupError):
            process.kill()
        await asyncio.gather(communication, return_exceptions=True)
        raise


def _safe_container_name(value: str) -> bool:
    return (
        bool(value) and len(value) <= 128 and all(char.isalnum() or char in "_-" for char in value)
    )


def _safe_label(value: str) -> bool:
    return (
        bool(value)
        and len(value) <= 256
        and all(char.isalnum() or char in "._=:/-" for char in value)
    )


def _safe_image_ref(value: str) -> bool:
    return (
        bool(value)
        and len(value) <= 512
        and "@" not in value
        and all(not char.isspace() and char != "\x00" for char in value)
        and not value.startswith("-")
    )


def _assert_within(root: Path, path: Path) -> None:
    resolved = path.expanduser().resolve()
    resolved.relative_to(root)
    if resolved == root:
        raise ValueError("sandbox mount cannot be the runtime root")


class OutputLimitExceeded(RuntimeError):
    pass


@dataclass(slots=True)
class _OutputBudget:
    remaining: int
    overflow: asyncio.Event
    lock: asyncio.Lock


async def _communicate(
    process: asyncio.subprocess.Process,
    max_output_bytes: int,
    overflow: asyncio.Event,
) -> tuple[bytes, bytes, int]:
    if process.stdout is None or process.stderr is None:
        raise RuntimeError("runtime pipes are unavailable")
    budget = _OutputBudget(max_output_bytes, overflow, asyncio.Lock())
    stdout_task = asyncio.create_task(_read_bounded(process.stdout, budget))
    stderr_task = asyncio.create_task(_read_bounded(process.stderr, budget))
    try:
        stdout, stderr, exit_code = await asyncio.gather(stdout_task, stderr_task, process.wait())
        if overflow.is_set():
            raise OutputLimitExceeded("sandbox output exceeds its limit")
        return stdout, stderr, exit_code
    finally:
        if not stdout_task.done():
            stdout_task.cancel()
        if not stderr_task.done():
            stderr_task.cancel()


async def _read_bounded(reader: asyncio.StreamReader, budget: _OutputBudget) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = await reader.read(65_536)
        if not chunk:
            return b"".join(chunks)
        async with budget.lock:
            if budget.remaining == 0:
                budget.overflow.set()
                continue
            if len(chunk) > budget.remaining:
                budget.remaining = 0
                budget.overflow.set()
                continue
            budget.remaining -= len(chunk)
        chunks.append(chunk)


async def _finish_communication(task: asyncio.Task[tuple[bytes, bytes, int]]) -> None:
    with suppress(OutputLimitExceeded, asyncio.CancelledError):
        await task


def _parse_cpu(value: object) -> int:
    if not isinstance(value, str):
        return 0
    try:
        return max(0, int(float(value.rstrip("%"))))
    except ValueError:
        return 0


def _parse_memory(value: object) -> int:
    if not isinstance(value, str) or "/" not in value:
        return 0
    raw = value.split("/", 1)[0].strip().upper()
    units = {
        "B": 1,
        "KB": 1000,
        "MB": 1000**2,
        "GB": 1000**3,
        "KIB": 1024,
        "MIB": 1024**2,
        "GIB": 1024**3,
    }
    for suffix, multiplier in sorted(units.items(), key=lambda item: len(item[0]), reverse=True):
        if raw.endswith(suffix):
            try:
                return max(0, int(float(raw[: -len(suffix)]) * multiplier))
            except ValueError:
                return 0
    try:
        return max(0, int(raw))
    except ValueError:
        return 0
