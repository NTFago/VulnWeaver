"""Normalize untrusted fuzz/crash output without executing generated artifacts."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import cast

from vulnweaver_contracts import (
    CrashRecord,
    FuzzRequest,
    FuzzResult,
    FuzzStatus,
    Identifier,
    SchemaVersion,
    StructuredFailure,
    ToolIdentity,
    validate_contract,
)

_FRAME_PREFIX = re.compile(r"^\s*(?:#\d+\s+)?(.+?)\s*$")
_ADDRESS = re.compile(r"0x[0-9a-fA-F]+")
_MAX_EXECUTIONS = 1_000_000_000
_MAX_DURATION_SECONDS = 86_400
_MAX_CRASHES = 10_000
_MAX_STACK_FRAMES = 256
_MAX_FRAME_CHARS = 2048


class CrashTriageError(ValueError):
    """A crash manifest entry is malformed or exceeds a configured limit."""


@dataclass(frozen=True, slots=True)
class FuzzBudgetLimits:
    max_executions: int
    max_duration_seconds: int
    max_crashes: int
    max_stack_frames: int = 256
    max_frame_chars: int = 2048
    max_manifest_entries: int = 10_000

    def __post_init__(self) -> None:
        if (
            min(
                self.max_executions,
                self.max_duration_seconds,
                self.max_crashes,
                self.max_stack_frames,
                self.max_frame_chars,
                self.max_manifest_entries,
            )
            < 1
        ):
            raise ValueError("fuzz budget limits must be positive")
        if self.max_executions > _MAX_EXECUTIONS:
            raise ValueError("fuzz execution budget exceeds the safe maximum")
        if self.max_duration_seconds > _MAX_DURATION_SECONDS:
            raise ValueError("fuzz duration budget exceeds the safe maximum")
        if self.max_crashes > _MAX_CRASHES:
            raise ValueError("fuzz crash budget exceeds the safe maximum")
        if self.max_stack_frames > _MAX_STACK_FRAMES:
            raise ValueError("fuzz stack frame budget exceeds the safe maximum")
        if self.max_frame_chars > _MAX_FRAME_CHARS:
            raise ValueError("fuzz stack frame length exceeds the safe maximum")
        if self.max_manifest_entries > _MAX_CRASHES:
            raise ValueError("fuzz manifest entry budget exceeds the safe maximum")
        if self.max_manifest_entries < self.max_crashes:
            raise ValueError("fuzz manifest entry budget cannot be below the crash budget")


@dataclass(slots=True)
class FuzzBudgetGate:
    limits: FuzzBudgetLimits
    started_at: datetime
    executions: int = 0
    crashes: int = 0

    def __post_init__(self) -> None:
        if self.started_at.tzinfo is None:
            raise ValueError("fuzz budget start must be timezone-aware")
        self.started_at = self.started_at.astimezone(UTC)

    @property
    def deadline(self) -> datetime:
        return self.started_at + timedelta(seconds=self.limits.max_duration_seconds)

    def expired(self, now: datetime) -> bool:
        if now.tzinfo is None:
            raise ValueError("fuzz budget clock must be timezone-aware")
        return now.astimezone(UTC) >= self.deadline

    def allow_execution(self, now: datetime) -> bool:
        if self.expired(now) or self.executions >= self.limits.max_executions:
            return False
        self.executions += 1
        return True

    def allow_crash(self) -> bool:
        if self.crashes >= self.limits.max_crashes:
            return False
        self.crashes += 1
        return True


def validate_fuzz_request(request: FuzzRequest) -> FuzzBudgetLimits:
    """Validate the public request before any fuzz tool is started."""

    try:
        validate_contract("FuzzRequest", request)
    except (TypeError, ValueError) as error:
        raise CrashTriageError("fuzz request does not satisfy the public contract") from error
    sandbox = request["sandbox_request"]
    if sandbox["id"] == request["id"]:
        raise CrashTriageError("fuzz request and nested sandbox request need distinct IDs")
    if sandbox["timeout_seconds"] > request["max_duration_seconds"]:
        raise CrashTriageError("sandbox timeout cannot exceed the fuzz duration budget")
    return FuzzBudgetLimits(
        max_executions=request["max_executions"],
        max_duration_seconds=request["max_duration_seconds"],
        max_crashes=request["max_crashes"],
    )


class CrashTriageService:
    """Create stable crash records and stack clusters from a bounded manifest."""

    def __init__(self, limits: FuzzBudgetLimits) -> None:
        self._limits = limits
        self._records: dict[str, CrashRecord] = {}
        self._clusters: dict[str, list[str]] = {}
        self._executions = 0

    def ingest(
        self,
        entry: Mapping[str, object],
        *,
        artifact_version_id: str,
        fuzz_tool: ToolIdentity,
        tool: ToolIdentity,
        created_at: str,
    ) -> CrashRecord | None:
        stack_frames = _normalize_frames(entry.get("stack_frames"), self._limits)
        if not stack_frames:
            raise CrashTriageError("crash entry must contain at least one stack frame")
        input_ref = _object_ref(entry.get("input_ref"), "input_ref")
        input_digest = _digest(entry.get("input_digest"), "input_digest")
        try:
            validate_contract("ToolIdentity", fuzz_tool)
            validate_contract("ToolIdentity", tool)
        except (TypeError, ValueError) as error:
            raise CrashTriageError("crash tool identities are invalid") from error
        stack_hash = _stack_hash(stack_frames)
        signal = _optional_text(entry.get("signal"), 128)
        exit_code = _optional_int(entry.get("exit_code"))
        stderr_ref = _optional_object_ref(entry.get("stderr_ref"))
        record_id = _stable_id(
            "crash",
            artifact_version_id,
            input_ref,
            input_digest,
            stack_hash,
            tool["name"],
            tool["version"],
            tool.get("image_digest") or "",
        )
        existing = self._records.get(record_id)
        if existing is not None:
            return existing
        if not self._within_crash_limit():
            return None
        record = CrashRecord(
            schema_version=SchemaVersion.VALUE_1_0_0,
            id=record_id,
            artifact_version_id=artifact_version_id,
            input_ref=input_ref,
            input_digest=input_digest,
            signal=signal,
            exit_code=exit_code,
            stack_frames=stack_frames,
            stack_hash=stack_hash,
            stderr_ref=stderr_ref,
            fuzz_tool=fuzz_tool,
            tool=tool,
            created_at=_timestamp(created_at),
        )
        validate_contract("CrashRecord", record)
        self._records[record_id] = record
        self._clusters.setdefault(stack_hash, []).append(record_id)
        return record

    def ingest_many(
        self,
        entries: list[Mapping[str, object]],
        *,
        artifact_version_id: str,
        fuzz_tool: ToolIdentity,
        tool: ToolIdentity,
        created_at: str,
    ) -> tuple[CrashRecord, ...]:
        """Ingest a bounded manifest while preserving deterministic first-seen order."""

        if len(entries) > self._limits.max_manifest_entries:
            raise CrashTriageError("crash manifest exceeds the configured entry limit")
        records: list[CrashRecord] = []
        seen: set[str] = set()
        for entry in entries:
            record = self.ingest(
                entry,
                artifact_version_id=artifact_version_id,
                fuzz_tool=fuzz_tool,
                tool=tool,
                created_at=created_at,
            )
            if record is not None and record["id"] not in seen:
                records.append(record)
                seen.add(record["id"])
        return tuple(records)

    def records(self) -> tuple[CrashRecord, ...]:
        return tuple(self._records[key] for key in sorted(self._records))

    def cluster(self, stack_hash: str) -> tuple[str, ...]:
        return tuple(sorted(self._clusters.get(stack_hash, [])))

    def build_result(
        self,
        job_id: str,
        *,
        status: FuzzStatus,
        coverage_percent: float | None,
        created_at: str,
        failure: StructuredFailure | None = None,
    ) -> FuzzResult:
        resolved_status = FuzzStatus(status)
        if resolved_status is FuzzStatus.SUCCEEDED and failure is not None:
            raise CrashTriageError("successful fuzz results cannot include a failure")
        if resolved_status is not FuzzStatus.SUCCEEDED and failure is None:
            raise CrashTriageError("non-successful fuzz results require a structured failure")
        result = FuzzResult(
            schema_version=SchemaVersion.VALUE_1_0_0,
            job_id=job_id,
            status=resolved_status,
            executions=self._executions,
            coverage_percent=coverage_percent,
            crash_ids=sorted(self._records),
            created_at=_timestamp(created_at),
            failure=failure,
        )
        validate_contract("FuzzResult", result)
        return result

    def set_execution_count(self, executions: int) -> None:
        if executions < 0 or executions > self._limits.max_executions:
            raise CrashTriageError("execution count exceeds fuzz budget")
        self._executions = executions

    def _within_crash_limit(self) -> bool:
        return len(self._records) < self._limits.max_crashes


def _normalize_frames(value: object, limits: FuzzBudgetLimits) -> list[str]:
    if not isinstance(value, list):
        raise CrashTriageError("stack_frames must be an array")
    raw_frames = cast(list[object], value)
    if len(raw_frames) > limits.max_stack_frames:
        raise CrashTriageError("stack frame count exceeds the configured limit")
    frames: list[str] = []
    for raw in raw_frames:
        if not isinstance(raw, str):
            raise CrashTriageError("stack frame must be text")
        matched = _FRAME_PREFIX.fullmatch(raw)
        frame = matched.group(1) if matched else raw.strip()
        frame = " ".join(frame.split())
        if len(frame) > limits.max_frame_chars:
            raise CrashTriageError("stack frame exceeds the configured limit")
        if frame:
            frames.append(frame)
    return frames


def _stack_hash(frames: list[str]) -> str:
    normalized = "\n".join(_ADDRESS.sub("<addr>", frame) for frame in frames)
    return "sha256:" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise CrashTriageError(f"{field} must be a canonical sha256 digest")
    return value


def _optional_text(value: object, limit: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise CrashTriageError("optional crash text must be non-empty text")
    normalized = " ".join(value.split())
    if len(normalized) > limit:
        raise CrashTriageError("optional crash text exceeds the configured limit")
    return normalized


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise CrashTriageError("exit_code must be an integer or null")
    if not -(2**31) <= value <= 2**31 - 1:
        raise CrashTriageError("exit_code exceeds the signed 32-bit range")
    return value


def _optional_object_ref(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not re.fullmatch(r"cas://sha256/[0-9a-f]{64}", value):
        raise CrashTriageError("stderr_ref must be a canonical CAS object reference")
    return value


def _object_ref(value: object, field: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"cas://sha256/[0-9a-f]{64}", value):
        raise CrashTriageError(f"{field} must be a canonical CAS object reference")
    return value


def _timestamp(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError) as error:
        raise CrashTriageError("crash timestamp must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None:
        raise CrashTriageError("crash timestamp must be timezone-aware")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _stable_id(prefix: str, *parts: str) -> Identifier:
    return f"{prefix}:{hashlib.sha256('\0'.join(parts).encode('utf-8')).hexdigest()[:32]}"
