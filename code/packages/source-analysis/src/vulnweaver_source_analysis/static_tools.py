"""Fixed-command adapters for Semgrep and cppcheck.

The adapters intentionally do not accept a command string.  They own the executable,
argument order, output format, and timeout boundary; deployment only supplies the
version-pinned ToolSpec and image digest.
"""

from __future__ import annotations

import json
import re
import subprocess
import xml.etree.ElementTree as ET
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

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


class StaticToolAdapter(Protocol):
    name: str

    def run(self, root: Path, *, timeout_seconds: int) -> StaticToolOutput: ...

    def parse(
        self, output: StaticToolOutput, *, artifact_version_id: str
    ) -> list[StaticAnalysisDiagnostic]: ...


class SubprocessStaticTool:
    """Run one fixed executable with bounded output and no shell."""

    def __init__(self, name: str, executable: str, arguments: Sequence[str]) -> None:
        self.name = name
        self._executable = executable
        self._arguments = tuple(arguments)

    def run(self, root: Path, *, timeout_seconds: int) -> StaticToolOutput:
        command = [self._executable, *self._arguments, "."]
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                timeout=timeout_seconds,
                shell=False,
                cwd=root,
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
        except subprocess.TimeoutExpired as error:
            return StaticToolOutput(
                self.name,
                None,
                StaticToolStatus.FAILED,
                None,
                _bytes(error.stdout),
                _bytes(error.stderr),
                "timeout",
            )
        status = (
            StaticToolStatus.SUCCEEDED if completed.returncode == 0 else StaticToolStatus.FAILED
        )
        return StaticToolOutput(
            self.name,
            _tool_version(self.name, completed.stdout, completed.stderr),
            status,
            completed.returncode,
            completed.stdout,
            completed.stderr,
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

    def run(self, root: Path, *, timeout_seconds: int) -> StaticToolOutput:
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
        return super().run(root, timeout_seconds=timeout_seconds)


class CppcheckAdapter(SubprocessStaticTool):
    def __init__(self, executable: str = "cppcheck") -> None:
        super().__init__(
            "cppcheck", executable, ("--xml", "--xml-version=2", "--enable=all", "--quiet")
        )


def parse_semgrep_output(raw: bytes, *, artifact_version_id: str) -> list[StaticAnalysisDiagnostic]:
    try:
        decoded: object = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return []
    if not isinstance(decoded, Mapping):
        return []
    document = cast(Mapping[str, object], decoded)
    raw_results = document.get("results")
    if not isinstance(raw_results, list):
        return []
    diagnostics: list[StaticAnalysisDiagnostic] = []
    for raw_result in cast(list[object], raw_results):
        if not isinstance(raw_result, Mapping):
            continue
        result = cast(Mapping[str, object], raw_result)
        check_id = result.get("check_id")
        path = result.get("path")
        start = result.get("start")
        end = result.get("end")
        extra_value = result.get("extra")
        if not isinstance(check_id, str) or not isinstance(path, str):
            continue
        if not isinstance(start, Mapping) or not isinstance(end, Mapping):
            continue
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
        return []
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


def _bytes(value: bytes | str | None) -> bytes:
    if value is None:
        return b""
    return value if isinstance(value, bytes) else value.encode("utf-8", errors="replace")


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
