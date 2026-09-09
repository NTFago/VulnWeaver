"""Fixed-command adapters for Semgrep and cppcheck.

The adapters intentionally do not accept a command string.  They own the executable,
argument order, output format, and timeout boundary; deployment only supplies the
version-pinned ToolSpec and image digest.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import threading
import xml.etree.ElementTree as ET
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Protocol, cast

from vulnweaver_contracts import (
    JsonObject,
    JsonValue,
    Severity,
    SourceLocation,
    StaticAnalysisDiagnostic,
    StaticToolStatus,
)


@dataclass(frozen=True, slots=True)
class StaticToolOutput:
    tool_name: str
    tool_version: str | None
    status: StaticToolStatus
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    reason: str | None = None


class StaticToolOutputError(ValueError):
    """The tool exited successfully but did not produce its declared format."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class StaticToolAdapter(Protocol):
    name: str

    def run(
        self,
        root: Path,
        *,
        timeout_seconds: int,
        max_output_bytes: int = 16 * 1024 * 1024,
    ) -> StaticToolOutput: ...

    def parse(
        self, output: StaticToolOutput, *, artifact_version_id: str
    ) -> list[StaticAnalysisDiagnostic]: ...


class SubprocessStaticTool:
    """Run one fixed executable with bounded output and no shell."""

    def __init__(self, name: str, executable: str, arguments: Sequence[str]) -> None:
        self.name = name
        self._executable = executable
        self._arguments = tuple(arguments)

    def run(
        self,
        root: Path,
        *,
        timeout_seconds: int,
        max_output_bytes: int = 16 * 1024 * 1024,
    ) -> StaticToolOutput:
        return self._run(
            root,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )

    def _run(
        self,
        root: Path,
        *,
        timeout_seconds: int,
        max_output_bytes: int,
        extra_environment: Mapping[str, str] | None = None,
    ) -> StaticToolOutput:
        if max_output_bytes < 1:
            raise ValueError("static tool output limit must be positive")
        command = [self._executable, *self._arguments, "."]
        try:
            process = subprocess.Popen(
                command,
                shell=False,
                cwd=root,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=_tool_environment(extra_environment),
            )
        except FileNotFoundError:
            return StaticToolOutput(
                self.name,
                None,
                StaticToolStatus.UNAVAILABLE,
                None,
                b"",
                b"",
                "executable_not_found",
            )
        assert process.stdout is not None
        assert process.stderr is not None
        budget = _CaptureBudget(max_output_bytes)
        stdout = bytearray()
        stderr = bytearray()
        readers = (
            threading.Thread(
                target=_read_bounded,
                args=(process.stdout, stdout, budget, process),
                daemon=True,
            ),
            threading.Thread(
                target=_read_bounded,
                args=(process.stderr, stderr, budget, process),
                daemon=True,
            ),
        )
        for reader in readers:
            reader.start()
        timed_out = False
        try:
            process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            process.wait()
        finally:
            for reader in readers:
                reader.join()
            process.stdout.close()
            process.stderr.close()

        captured_stdout = bytes(stdout)
        captured_stderr = bytes(stderr)
        if budget.exceeded.is_set():
            return StaticToolOutput(
                self.name,
                None,
                StaticToolStatus.FAILED,
                process.returncode,
                captured_stdout,
                captured_stderr,
                "output_limit_exceeded",
            )
        if timed_out:
            return StaticToolOutput(
                self.name,
                None,
                StaticToolStatus.FAILED,
                None,
                captured_stdout,
                captured_stderr,
                "timeout",
            )
        status = StaticToolStatus.SUCCEEDED if process.returncode == 0 else StaticToolStatus.FAILED
        return StaticToolOutput(
            self.name,
            _tool_version(self.name, captured_stdout, captured_stderr),
            status,
            process.returncode,
            captured_stdout,
            captured_stderr,
            None if status is StaticToolStatus.SUCCEEDED else "tool_exit_nonzero",
        )

    def parse(
        self, output: StaticToolOutput, *, artifact_version_id: str
    ) -> list[StaticAnalysisDiagnostic]:
        if self.name == "semgrep":
            return parse_semgrep_output(output.stdout, artifact_version_id=artifact_version_id)
        if self.name == "cppcheck":
            raw = output.stdout or output.stderr
            return parse_cppcheck_output(raw, artifact_version_id=artifact_version_id)
        raise ValueError(f"unsupported static tool {self.name!r}")


class SemgrepAdapter(SubprocessStaticTool):
    def __init__(self, executable: str = "semgrep", config_path: str | None = None) -> None:
        # A local config is required: ``--config auto`` can fetch rules and would
        # violate the worker's default no-network execution boundary.
        config = config_path or "/etc/vulnweaver/tool-specs/semgrep-rules.yml"
        self._config_path = Path(config)
        super().__init__(
            "semgrep",
            executable,
            ("--json", "--no-git-ignore", "--metrics", "off", "--config", config),
        )

    def run(
        self,
        root: Path,
        *,
        timeout_seconds: int,
        max_output_bytes: int = 16 * 1024 * 1024,
    ) -> StaticToolOutput:
        if not self._config_path.is_file():
            return StaticToolOutput(
                self.name,
                None,
                StaticToolStatus.UNAVAILABLE,
                None,
                b"",
                b"",
                "rules_not_installed",
            )
        # Semgrep writes settings and user logs even when telemetry and version
        # checks are disabled.  The worker root and source tree are intentionally
        # read-only, so give only this process a disposable home and settings
        # location under the writable tmpfs rather than weakening either boundary.
        with tempfile.TemporaryDirectory(prefix="vulnweaver-semgrep-") as state_directory:
            settings_file = Path(state_directory) / "settings.yml"
            return self._run(
                root,
                timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes,
                extra_environment={
                    "HOME": state_directory,
                    "SEMGREP_SETTINGS_FILE": str(settings_file),
                },
            )


class CppcheckAdapter(SubprocessStaticTool):
    def __init__(self, executable: str = "cppcheck") -> None:
        super().__init__(
            "cppcheck", executable, ("--xml", "--xml-version=2", "--enable=all", "--quiet")
        )


def parse_semgrep_output(raw: bytes, *, artifact_version_id: str) -> list[StaticAnalysisDiagnostic]:
    try:
        decoded: object = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise StaticToolOutputError("semgrep.invalid_json_output") from None
    if not isinstance(decoded, Mapping):
        raise StaticToolOutputError("semgrep.invalid_json_document")
    document = cast(Mapping[str, object], decoded)
    raw_results = document.get("results")
    if not isinstance(raw_results, list):
        raise StaticToolOutputError("semgrep.results_missing")
    diagnostics: list[StaticAnalysisDiagnostic] = []
    for raw_result in cast(list[object], raw_results):
        if not isinstance(raw_result, Mapping):
            raise StaticToolOutputError("semgrep.invalid_result")
        result = cast(Mapping[str, object], raw_result)
        check_id = result.get("check_id")
        path = result.get("path")
        start = result.get("start")
        end = result.get("end")
        extra_value = result.get("extra")
        if not isinstance(check_id, str) or not isinstance(path, str):
            raise StaticToolOutputError("semgrep.invalid_result")
        if not isinstance(start, Mapping) or not isinstance(end, Mapping):
            raise StaticToolOutputError("semgrep.invalid_result")
        start_mapping = cast(Mapping[str, object], start)
        end_mapping = cast(Mapping[str, object], end)
        extra: Mapping[str, object] = (
            cast(Mapping[str, object], extra_value) if isinstance(extra_value, Mapping) else {}
        )
        message = extra.get("message")
        if not isinstance(message, str) or not message:
            message = check_id
        metadata_value = extra.get("metadata")
        metadata: Mapping[str, object] = (
            cast(Mapping[str, object], metadata_value)
            if isinstance(metadata_value, Mapping)
            else {}
        )
        properties: JsonObject = {
            str(key): cast(JsonValue, value)
            for key, value in extra.items()
            if key not in {"message", "metadata"}
        }
        properties["metadata"] = cast(JsonObject, dict(metadata))
        rule_id = _normalize_semgrep_rule_id(check_id)
        diagnostics.append(
            StaticAnalysisDiagnostic(
                tool_name="semgrep",
                rule_id=rule_id,
                severity=_severity(extra.get("severity")),
                message=message[:16384],
                location=_location(artifact_version_id, path, start_mapping, end_mapping),
                cwe_ids=_cwe_ids(metadata.get("cwe")),
                properties=properties,
            )
        )
    return diagnostics


def parse_cppcheck_output(
    raw: bytes, *, artifact_version_id: str
) -> list[StaticAnalysisDiagnostic]:
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        raise StaticToolOutputError("cppcheck.invalid_xml_output") from None
    diagnostics: list[StaticAnalysisDiagnostic] = []
    for error in root.findall(".//error"):
        rule_id = error.attrib.get("id")
        message = error.attrib.get("msg")
        if not rule_id or not message:
            continue
        location_node = error.find("location")
        if location_node is None:
            continue
        path = location_node.attrib.get("file")
        line = _positive_int(location_node.attrib.get("line"))
        column = _positive_int(location_node.attrib.get("column")) or 1
        if not path or line is None:
            continue
        cwe = error.attrib.get("cwe") or error.attrib.get("cwe_id")
        properties: JsonObject = {
            key: value
            for key, value in error.attrib.items()
            if key not in {"id", "msg", "severity", "cwe", "cwe_id"}
        }
        diagnostics.append(
            StaticAnalysisDiagnostic(
                tool_name="cppcheck",
                rule_id=rule_id,
                severity=_severity(error.attrib.get("severity")),
                message=message[:16384],
                location=SourceLocation(
                    artifact_version_id=artifact_version_id,
                    path=path,
                    start_line=line,
                    start_column=column,
                    end_line=line,
                    end_column=column,
                ),
                cwe_ids=_cwe_ids(cwe),
                properties=properties,
            )
        )
    return diagnostics


def _normalize_semgrep_rule_id(value: str) -> str:
    marker = "vulnweaver."
    index = value.find(marker)
    return value[index:] if index >= 0 else value


def _location(
    artifact_version_id: str,
    path: str,
    start: Mapping[str, object],
    end: Mapping[str, object],
) -> SourceLocation:
    start_line = _positive_int(start.get("line")) or 1
    start_column = _positive_int(start.get("col")) or 1
    end_line = _positive_int(end.get("line")) or start_line
    end_column = _positive_int(end.get("col")) or start_column
    return SourceLocation(
        artifact_version_id=artifact_version_id,
        path=path,
        start_line=start_line,
        start_column=start_column,
        end_line=end_line,
        end_column=end_column,
    )


def _severity(value: object) -> Severity:
    normalized = str(value or "").casefold()
    return {
        "critical": Severity.CRITICAL,
        "error": Severity.HIGH,
        "high": Severity.HIGH,
        "warning": Severity.MEDIUM,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
        "information": Severity.INFO,
        "portability": Severity.INFO,
        "style": Severity.INFO,
        "performance": Severity.LOW,
    }.get(normalized, Severity.MEDIUM)


def _cwe_ids(value: object) -> list[str]:
    values = cast(list[object], value) if isinstance(value, list) else [value]
    result: list[str] = []
    for item in values:
        if not isinstance(item, str):
            continue
        for token in item.replace(",", " ").split():
            normalized = token if token.upper().startswith("CWE-") else f"CWE-{token}"
            if normalized not in result and normalized[4:].isdigit():
                result.append(normalized)
    return result


def _positive_int(value: object) -> int | None:
    try:
        number = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


class _CaptureBudget:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.consumed = 0
        self.exceeded = threading.Event()
        self.lock = threading.Lock()

    def take(self, chunk: bytes) -> bytes:
        with self.lock:
            remaining = self.limit - self.consumed
            accepted = chunk[: max(remaining, 0)]
            self.consumed += len(accepted)
            if len(accepted) != len(chunk):
                self.exceeded.set()
            return accepted


def _read_bounded(
    stream: BinaryIO,
    output: bytearray,
    budget: _CaptureBudget,
    process: subprocess.Popen[bytes],
) -> None:
    while chunk := stream.read(64 * 1024):
        output.extend(budget.take(chunk))
        if budget.exceeded.is_set():
            with suppress(OSError):
                process.kill()
            return


def _tool_environment(extra_environment: Mapping[str, str] | None = None) -> dict[str, str]:
    allowed = {
        "LANG",
        "LC_ALL",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "TMP",
        "TEMP",
        "TMPDIR",
        "WINDIR",
    }
    environment = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    if extra_environment:
        environment.update(extra_environment)
    return environment


def _tool_version(tool_name: str, stdout: bytes, stderr: bytes) -> str | None:
    if tool_name == "semgrep":
        try:
            document = json.loads(stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            document = None
        if isinstance(document, Mapping):
            version = cast(Mapping[str, object], document).get("version")
            if isinstance(version, str) and version:
                return version[:128]
        return None
    if tool_name == "cppcheck":
        match = re.search(rb"<cppcheck\s+version=\"([^\"]+)\"", stdout + stderr)
        if match is not None:
            return match.group(1).decode("utf-8", errors="replace")[:128]
    return _version_from_output(stdout, stderr)


def _version_from_output(stdout: bytes, stderr: bytes) -> str | None:
    for raw in (stdout, stderr):
        line = raw.decode("utf-8", errors="replace").splitlines()
        if line:
            return line[0][:128]
    return None
