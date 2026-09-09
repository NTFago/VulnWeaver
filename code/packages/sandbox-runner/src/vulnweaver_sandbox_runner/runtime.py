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


@dataclass(slots=True)
class _RuntimeUsage:
    last_sample_at: float
    cpu_millis: float = 0.0
    peak_memory_bytes: int = 0


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
        docker_host_root: str | Path | None = None,
        command_timeout_seconds: float = 15.0,
    ) -> None:
        if not 1 <= command_timeout_seconds <= 60:
            raise ValueError("Docker command timeout must be between 1 and 60 seconds")
        self._docker = docker_executable
        self._command_timeout_seconds = command_timeout_seconds
        self._root = Path(root).expanduser().resolve()
        self._docker_host_root = (
            Path(docker_host_root).expanduser().resolve() if docker_host_root is not None else None
        )
        if self._docker_host_root is not None:
            self._docker_host_root.mkdir(parents=True, exist_ok=True)
        self._root.mkdir(parents=True, exist_ok=True)

    async def run(self, request: RuntimeRequest, cancellation: asyncio.Event) -> RuntimeExecution:
        self._validate_request(request)
        started = time.monotonic()
        await self._create_output_volume(request)
        await self._start_output_keeper(request)
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
        usage = _RuntimeUsage(last_sample_at=time.monotonic())
        usage_stopped = asyncio.Event()
        usage_task = asyncio.create_task(
            self._monitor_usage(request.container_name, usage, usage_stopped)
        )
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
            await _finish_usage_monitor(usage_task, usage_stopped)
            await self._copy_outputs(request.container_name, request.output_dir)
            return RuntimeExecution(
                status=status,
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                duration_millis=max(0, int((time.monotonic() - started) * 1000)),
                cpu_millis=max(0, round(usage.cpu_millis)),
                memory_bytes=usage.peak_memory_bytes,
            )
        finally:
            await _finish_usage_monitor(usage_task, usage_stopped)
            cancelled.cancel()
            overflowed.cancel()
            if not communicate.done():
                communicate.cancel()
            await asyncio.gather(cancelled, overflowed, communicate, return_exceptions=True)

    async def cleanup(self, container_name: str) -> bool:
        if not _safe_container_name(container_name):
            return False
        try:
            container_removed = await self._remove_resource("container", container_name)
        except (OSError, TimeoutError, RuntimeError):
            container_removed = False
        try:
            keeper_removed = await self._remove_resource(
                "container", _output_keeper_name(container_name)
            )
        except (OSError, TimeoutError, RuntimeError):
            keeper_removed = False
        try:
            volume_removed = await self._remove_resource(
                "volume", _output_volume_name(container_name)
            )
        except (OSError, TimeoutError, RuntimeError):
            volume_removed = False
        return container_removed and keeper_removed and volume_removed

    async def list_owned(self, label: str) -> tuple[str, ...]:
        if not _safe_label(label):
            return ()
        containers, volumes = await asyncio.gather(
            self._list_resources("container", label),
            self._list_resources("volume", label),
        )
        names = set(containers)
        for container in containers:
            if container.endswith("-keeper"):
                names.discard(container)
                names.add(container[: -len("-keeper")])
        for volume in volumes:
            if volume.endswith("-output"):
                names.add(volume[: -len("-output")])
        return tuple(sorted(name for name in names if _safe_container_name(name)))

    def build_arguments(self, request: RuntimeRequest) -> tuple[str, ...]:
        self.validate_request(request)
        return self._run_arguments(request)

    def build_output_volume_arguments(self, request: RuntimeRequest) -> tuple[str, ...]:
        self.validate_request(request)
        return self._output_volume_arguments(request)

    def build_output_keeper_arguments(self, request: RuntimeRequest) -> tuple[str, ...]:
        self.validate_request(request)
        return self._output_keeper_arguments(request)

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
            "--hostname",
            "vulnweaver-sandbox",
            "--add-host",
            "vulnweaver-sandbox:127.0.0.1",
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
            "--tmpfs",
            f"/work:rw,exec,nosuid,size={request.resource_budget['disk_bytes']}",
            "--mount",
            f"type=bind,src={self._docker_visible_path(request.input_dir)},dst=/input,readonly",
            "--mount",
            f"type=volume,src={_output_volume_name(request.container_name)},"
            "dst=/output,volume-nocopy",
            "--user",
            "10001:10001",
            "--entrypoint",
            request.argv[0],
            image,
            *request.argv[1:],
        )

    def _validate_request(self, request: RuntimeRequest) -> None:
        if not _safe_container_name(request.container_name):
            raise ValueError("invalid sandbox container name")
        if not _safe_container_name(_output_keeper_name(request.container_name)):
            raise ValueError("sandbox container name leaves no room for runtime helpers")
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

    async def _create_output_volume(self, request: RuntimeRequest) -> None:
        process = await asyncio.create_subprocess_exec(
            *self._output_volume_arguments(request),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_runtime_environment(),
        )
        _, stderr = await _communicate_with_timeout(process, self._command_timeout_seconds)
        if process.returncode != 0:
            raise RuntimeError(
                "Docker could not create the quota-enforced sandbox output volume: "
                + stderr.decode("utf-8", "replace")[:512]
            )

    def _output_volume_arguments(self, request: RuntimeRequest) -> tuple[str, ...]:
        return (
            self._docker,
            "volume",
            "create",
            "--driver",
            "local",
            "--label",
            request.label,
            "--opt",
            "type=tmpfs",
            "--opt",
            "device=tmpfs",
            "--opt",
            (f"o=size={request.resource_budget['disk_bytes']},uid=10001,gid=10001,mode=0700"),
            _output_volume_name(request.container_name),
        )

    def _docker_visible_path(self, path: Path) -> Path:
        if self._docker_host_root is None:
            return path
        relative = path.relative_to(self._root)
        return self._docker_host_root / relative

    async def _start_output_keeper(self, request: RuntimeRequest) -> None:
        process = await asyncio.create_subprocess_exec(
            *self._output_keeper_arguments(request),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_runtime_environment(),
        )
        _, stderr = await _communicate_with_timeout(process, self._command_timeout_seconds)
        if process.returncode != 0:
            raise RuntimeError(
                "Docker could not start the sandbox output keeper: "
                + stderr.decode("utf-8", "replace")[:512]
            )

    def _output_keeper_arguments(self, request: RuntimeRequest) -> tuple[str, ...]:
        image = f"{request.image_ref}@{request.image_digest}"
        return (
            self._docker,
            "run",
            "--detach",
            "--name",
            _output_keeper_name(request.container_name),
            "--label",
            request.label,
            "--network",
            "none",
            "--hostname",
            "vulnweaver-sandbox",
            "--add-host",
            "vulnweaver-sandbox:127.0.0.1",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges=true",
            "--pids-limit",
            "8",
            "--memory",
            str(16 * 1024 * 1024),
            "--cpus",
            "0.01",
            "--mount",
            (
                f"type=volume,src={_output_volume_name(request.container_name)},"
                "dst=/output,readonly,volume-nocopy"
            ),
            "--user",
            "10001:10001",
            "--entrypoint",
            "/bin/sleep",
            image,
            "2147483647",
        )

    async def _copy_outputs(self, container_name: str, output_dir: Path) -> None:
        process = await asyncio.create_subprocess_exec(
            self._docker,
            "cp",
            f"{_output_keeper_name(container_name)}:/output/.",
            str(output_dir),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_runtime_environment(),
        )
        _, stderr = await _communicate_with_timeout(process, self._command_timeout_seconds)
        if process.returncode != 0:
            raise RuntimeError(
                "Docker could not collect sandbox outputs: "
                + stderr.decode("utf-8", "replace")[:512]
            )

    async def _monitor_usage(
        self,
        container_name: str,
        usage: _RuntimeUsage,
        stopped: asyncio.Event,
    ) -> None:
        while not stopped.is_set():
            try:
                cpu_percent, memory_bytes = await self._usage(container_name)
            except (OSError, TimeoutError, RuntimeError):
                cpu_percent, memory_bytes = 0.0, 0
            sampled_at = time.monotonic()
            elapsed_millis = max(0.0, (sampled_at - usage.last_sample_at) * 1000)
            usage.cpu_millis += _cpu_millis_for_interval(cpu_percent, elapsed_millis)
            usage.peak_memory_bytes = max(usage.peak_memory_bytes, memory_bytes)
            usage.last_sample_at = sampled_at
            try:
                await asyncio.wait_for(stopped.wait(), timeout=0.25)
            except TimeoutError:
                continue

    async def _usage(self, container_name: str) -> tuple[float, int]:
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
            cpu = _parse_cpu_percent(payload.get("CPUPerc"))
            memory = _parse_memory(payload.get("MemUsage"))
            return cpu, memory
        except (IndexError, TypeError, ValueError, json.JSONDecodeError):
            return 0.0, 0

    async def _list_resources(self, kind: str, label: str) -> tuple[str, ...]:
        arguments = (
            ("ps", "--all", "--filter", f"label={label}", "--format", "{{.Names}}")
            if kind == "container"
            else ("volume", "ls", "--filter", f"label={label}", "--format", "{{.Name}}")
        )
        process = await asyncio.create_subprocess_exec(
            self._docker,
            *arguments,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_runtime_environment(),
        )
        stdout, _ = await _communicate_with_timeout(process, self._command_timeout_seconds)
        if process.returncode != 0:
            return ()
        return tuple(stdout.decode("utf-8", "replace").splitlines())

    async def _remove_resource(self, kind: str, name: str) -> bool:
        arguments = (
            ("rm", "--force", name) if kind == "container" else ("volume", "rm", "--force", name)
        )
        process = await asyncio.create_subprocess_exec(
            self._docker,
            *arguments,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_runtime_environment(),
        )
        _, stderr = await _communicate_with_timeout(process, self._command_timeout_seconds)
        if process.returncode == 0:
            return True
        message = stderr.decode("utf-8", "replace").lower()
        return f"no such {kind}" in message


def _runtime_environment() -> dict[str, str]:
    return {"PATH": os.environ.get("PATH", ""), "LANG": "C", "LC_ALL": "C"}


async def _finish_usage_monitor(task: asyncio.Task[None], stopped: asyncio.Event) -> None:
    stopped.set()
    if task.done():
        await asyncio.gather(task, return_exceptions=True)
        return
    try:
        await asyncio.wait_for(asyncio.shield(task), timeout=2.0)
    except TimeoutError:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


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


def _output_volume_name(container_name: str) -> str:
    return f"{container_name}-output"


def _output_keeper_name(container_name: str) -> str:
    return f"{container_name}-keeper"


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


def _parse_cpu_percent(value: object) -> float:
    if not isinstance(value, str):
        return 0.0
    try:
        return max(0.0, float(value.rstrip("%")))
    except ValueError:
        return 0.0


def _cpu_millis_for_interval(cpu_percent: float, elapsed_millis: float) -> float:
    return max(0.0, cpu_percent) * max(0.0, elapsed_millis) / 100


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
