"""Read-only investigation tools for the agentic code audit.

The audit agent is not handed a pre-truncated dump of functions. It is given a
catalog of read-only investigation tools and decides for itself which function
to open, which call edge to follow and which string to search for. Every tool is
an in-process ``ToolSpec``, so each planned step still passes the Policy Engine
before it runs, and every observation is bounded before it reaches the model.

Nothing here executes a sample. Dynamic analysis stays behind the Sandbox
Runner; these tools only read the immutable index, the artifact store and the
rows the pipeline already produced.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import cast

from vulnweaver_artifact_store import ArtifactStore, ArtifactStoreError
from vulnweaver_contracts import (
    ArtifactKind,
    ArtifactVersion,
    EvidenceType,
    Finding,
    JsonObject,
    JsonValue,
    PairEdge,
    PairFunction,
    PairNode,
    ResourceBudget,
)
from vulnweaver_pair import binary_address_of, build_call_path_steps, pseudocode_text
from vulnweaver_persistence import Database, Repositories
from vulnweaver_source_analysis import SourceExcerptReader, SourceImportError
from vulnweaver_tool_runtime import ScheduledToolCall

from vulnweaver_orchestrator.source_facts import SourceReviewFactLoader

# The audit tools are in-process readers: they have no container image. The
# registry contract still requires a pinned digest, so read-only tools reuse the
# documented placeholder convention from ``reverse_planning``.
IN_PROCESS_DIGEST = "sha256:" + "0" * 64

FUNCTION_LIST_TOOL = "code-function-list"
FUNCTION_READ_TOOL = "code-function-read"
CODE_SEARCH_TOOL = "code-search"
CALL_NEIGHBORHOOD_TOOL = "call-neighborhood"
ARTIFACT_FACTS_TOOL = "artifact-facts"
STATIC_LEADS_TOOL = "static-leads"
CRITICAL_LOGIC_TOOL = "critical-logic"
FINDING_REPORT_TOOL = "finding-report"

_MAX_LIST_LIMIT = 200
_MAX_SEARCH_LIMIT = 100
_MAX_SEARCH_FILES = 200
_MAX_TEXT_CHARS = 16_384
_MAX_SOURCE_PATTERN_CHARS = 256
_MAX_NEIGHBORHOOD_DEPTH = 3
_MAX_FACTS_ITEMS = 100
_MAX_REPORTED_FINDINGS = 32

_SOURCE_KINDS = (ArtifactKind.SOURCE_ARCHIVE, ArtifactKind.SOURCE_REPOSITORY)
_BINARY_KINDS = (ArtifactKind.ELF, ArtifactKind.PE, ArtifactKind.DERIVED)
_ALL_KINDS = [kind.value for kind in (*_SOURCE_KINDS, *_BINARY_KINDS)]


def _spec(
    name: str, command_schema: JsonObject, *, output_schema: JsonObject | None = None
) -> JsonObject:
    return cast(
        JsonObject,
        {
            "schema_version": "1.0.0",
            "name": name,
            "version": "1.0.0",
            "image_digest": IN_PROCESS_DIGEST,
            "risk_level": "low",
            "accepted_artifacts": _ALL_KINDS,
            "command_schema": command_schema,
            "output_schema": output_schema or {"type": "object"},
            "network_policy": {"access": "none", "allowed_hosts": []},
            "filesystem_policy": {
                "input_read_only": True,
                "isolated_output": True,
                "allow_host_paths": False,
            },
            "resource_limits": cast(
                ResourceBudget,
                {
                    "max_model_tokens": 0,
                    "cpu_millis": 1_000,
                    "memory_bytes": 256 * 1024 * 1024,
                    "disk_bytes": 64 * 1024 * 1024,
                    "max_tool_concurrency": 1,
                    "max_dynamic_runs": 0,
                    "timeout_seconds": 300,
                },
            ),
            "approval_required": False,
            "timeout_seconds": 120,
            "retry_policy": {
                "max_attempts": 1,
                "backoff_seconds": 0,
                "retryable_failure_kinds": [],
            },
        },
    )


def _object(properties: JsonObject, required: Sequence[str] = ()) -> JsonObject:
    return cast(
        JsonObject,
        {
            "type": "object",
            "additionalProperties": False,
            "required": list(required),
            "properties": properties,
        },
    )


AUDIT_TOOLS: tuple[JsonObject, ...] = (
    _spec(
        FUNCTION_LIST_TOOL,
        _object(
            {
                "path_prefix": {"type": "string", "minLength": 1, "maxLength": 512},
                "name_pattern": {"type": "string", "minLength": 1, "maxLength": 256},
                "binary_only": {"type": "boolean"},
                "limit": {"type": "integer", "minimum": 1, "maximum": _MAX_LIST_LIMIT},
            }
        ),
    ),
    _spec(
        FUNCTION_READ_TOOL,
        cast(
            JsonObject,
            {
                "type": "object",
                "additionalProperties": False,
                "oneOf": [
                    {"required": ["function_id"]},
                    {"required": ["path", "start_line"]},
                ],
                "properties": {
                    "function_id": {"type": "string", "minLength": 1, "maxLength": 512},
                    "path": {"type": "string", "minLength": 1, "maxLength": 1024},
                    "start_line": {"type": "integer", "minimum": 1},
                },
            },
        ),
    ),
    _spec(
        CODE_SEARCH_TOOL,
        _object(
            {
                "pattern": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": _MAX_SOURCE_PATTERN_CHARS,
                },
                "scope": {"type": "string", "enum": ["source", "binary_strings"]},
                "limit": {"type": "integer", "minimum": 1, "maximum": _MAX_SEARCH_LIMIT},
            },
            ("pattern",),
        ),
    ),
    _spec(
        CALL_NEIGHBORHOOD_TOOL,
        _object(
            {
                "function_id": {"type": "string", "minLength": 1, "maxLength": 512},
                "depth": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": _MAX_NEIGHBORHOOD_DEPTH,
                },
            },
            ("function_id",),
        ),
    ),
    _spec(
        ARTIFACT_FACTS_TOOL,
        _object(
            {
                "kind": {
                    "type": "string",
                    "enum": ["summary", "imports", "strings", "sections", "obfuscation"],
                }
            },
            ("kind",),
        ),
    ),
    _spec(STATIC_LEADS_TOOL, _object({})),
    _spec(CRITICAL_LOGIC_TOOL, _object({})),
    _spec(
        FINDING_REPORT_TOOL,
        cast(
            JsonObject,
            {
                "type": "object",
                "additionalProperties": False,
                "oneOf": [
                    {
                        "required": [
                            "cwe_id",
                            "title",
                            "severity",
                            "rationale",
                            "path",
                            "start_line",
                        ]
                    },
                    {"required": ["cwe_id", "title", "severity", "rationale", "address"]},
                ],
                "properties": {
                    "cwe_id": {"type": "string", "pattern": "^CWE-[0-9]{1,6}$"},
                    "title": {"type": "string", "minLength": 1, "maxLength": 256},
                    "severity": {
                        "type": "string",
                        "enum": ["info", "low", "medium", "high", "critical"],
                    },
                    "rationale": {"type": "string", "minLength": 1, "maxLength": 4096},
                    "path": {"type": "string", "minLength": 1, "maxLength": 1024},
                    "start_line": {"type": "integer", "minimum": 1},
                    "end_line": {"type": "integer", "minimum": 1},
                    "address": {"type": "integer", "minimum": 0},
                    "verification_request": {
                        "type": "string",
                        "enum": ["fuzz", "none"],
                    },
                    "verification_reason": {"type": "string", "minLength": 1, "maxLength": 1024},
                },
            },
        ),
    ),
)


@dataclass(frozen=True, slots=True)
class AuditFunctionRef:
    """One indexed function plus the version whose graph actually holds it."""

    version_id: str
    function: PairFunction


@dataclass(frozen=True, slots=True)
class ReportedFinding:
    """A candidate the agent asked to record, before anchoring."""

    cwe_id: str
    title: str
    severity: str
    rationale: str
    path: str | None
    start_line: int | None
    end_line: int | None
    address: int | None
    verification_request: str | None = None
    verification_reason: str | None = None
    step_id: str = ""

    def as_document(self) -> JsonObject:
        """Shape matching ``SemanticAuditFinding`` so projection is shared."""

        document: JsonObject = {
            "cwe_id": self.cwe_id,
            "title": self.title,
            "severity": self.severity,
            "rationale": self.rationale,
        }
        if self.address is not None:
            document["address"] = self.address
        else:
            document["path"] = self.path
            document["start_line"] = self.start_line
            if self.end_line is not None:
                document["end_line"] = self.end_line
        return document


@dataclass(slots=True)
class AuditWorkspaceLimits:
    max_search_files: int = _MAX_SEARCH_FILES
    max_text_chars: int = _MAX_TEXT_CHARS


class AuditWorkspace:
    """Task-scoped read-only view the audit agent investigates through."""

    def __init__(
        self,
        database: Database,
        store: ArtifactStore,
        task_id: str,
        *,
        limits: AuditWorkspaceLimits | None = None,
        fact_loader: SourceReviewFactLoader | None = None,
    ) -> None:
        self.database = database
        self.store = store
        self.task_id = task_id
        self.limits = limits or AuditWorkspaceLimits()
        self.fact_loader = fact_loader or SourceReviewFactLoader(database, store)
        self._functions: list[AuditFunctionRef] = []
        self._functions_by_id: dict[str, AuditFunctionRef] = {}
        self._version_kinds: dict[str, ArtifactKind] = {}
        self._versions: dict[str, ArtifactVersion] = {}
        self._files: dict[tuple[str, str], str | None] = {}
        self._documents: dict[str, JsonObject | None] = {}
        self._reader: SourceExcerptReader | None = None

    async def load(self) -> None:
        """Index the task's artifact versions and every function they hold."""

        async with self.database.transaction() as repositories:
            task = await repositories.tasks.get(self.task_id)
            for version_id in sorted(task["artifact_version_ids"]):
                version = await repositories.artifacts.get_version(version_id)
                artifact = await repositories.artifacts.get(version["artifact_id"])
                kind = ArtifactKind(artifact["kind"])
                self._version_kinds[version_id] = kind
                self._versions[version_id] = version
                # Binary graphs are stored under the derived analysis version,
                # so the functions' own artifact_version_id is authoritative.
                for function in await repositories.pair.list_functions(version_id):
                    ref = AuditFunctionRef(
                        version_id=function["artifact_version_id"], function=function
                    )
                    if ref.function["id"] in self._functions_by_id:
                        continue
                    self._functions_by_id[ref.function["id"]] = ref
                    self._functions.append(ref)
        self._functions.sort(key=_function_sort_key)

    @property
    def artifact_kinds(self) -> dict[str, ArtifactKind | str]:
        return {version_id: kind for version_id, kind in self._version_kinds.items()}

    @property
    def function_count(self) -> int:
        return len(self._functions)

    def version_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._version_kinds))

    def function_refs(self) -> tuple[AuditFunctionRef, ...]:
        return tuple(self._functions)

    # -- tools -------------------------------------------------------------

    async def list_functions(
        self,
        *,
        path_prefix: str | None,
        name_pattern: str | None,
        binary_only: bool,
        limit: int,
    ) -> JsonObject:
        matcher = _compile(name_pattern)
        selected: list[JsonObject] = []
        total = 0
        for ref in self._functions:
            function = ref.function
            if binary_only and function["binary_location"] is None:
                continue
            source = function["source_location"]
            if path_prefix is not None and (
                source is None or not source["path"].startswith(path_prefix)
            ):
                continue
            if matcher is not None and matcher.search(function["name"]) is None:
                continue
            total += 1
            if len(selected) < limit:
                selected.append(_function_summary(ref))
        return cast(
            JsonObject,
            {"matched": total, "returned": len(selected), "functions": selected},
        )

    async def read_function(
        self,
        *,
        function_id: str | None,
        path: str | None,
        start_line: int | None,
    ) -> JsonObject:
        ref = await self._resolve_function(
            function_id=function_id, path=path, start_line=start_line
        )
        if ref is None:
            return {"found": False, "reason_code": "function_not_indexed"}
        function = ref.function
        code, code_kind, truncated = await self._function_code(ref)
        summary = _function_summary(ref)
        summary.update(
            {
                "found": True,
                "signature": function["signature"],
                "code_kind": code_kind,
                "code": code,
                "code_truncated": truncated,
            }
        )
        if function["source_location"] is not None:
            summary["end_line"] = function["source_location"]["end_line"]
        return summary

    async def search(self, *, pattern: str, scope: str, limit: int) -> JsonObject:
        matcher = _compile(pattern)
        if matcher is None:
            return {"matches": [], "reason_code": "search_pattern_invalid"}
        if scope == "binary_strings":
            return await self._search_binary_strings(matcher, limit)
        return await self._search_source(matcher, limit)

    async def neighborhood(self, *, function_id: str, depth: int) -> JsonObject:
        ref = self._functions_by_id.get(function_id)
        if ref is None:
            return {"found": False, "reason_code": "function_not_indexed"}
        async with self.database.transaction() as repositories:
            raw = await repositories.pair.neighborhood(
                ref.version_id, function_id, depth=depth
            )
        functions = cast(list[PairFunction], raw["functions"])
        nodes = cast(list[PairNode], raw["nodes"])
        edges = cast(list[PairEdge], raw["edges"])
        steps = build_call_path_steps(functions, nodes, edges, function_id)
        return cast(
            JsonObject,
            {
                "found": True,
                "function_id": function_id,
                "depth": depth,
                "related": [
                    _related_summary(item)
                    for item in functions
                    if item["id"] != function_id
                ],
                "call_path": [cast(JsonObject, dict(step)) for step in steps],
            },
        )

    async def artifact_facts(self, *, kind: str) -> JsonObject:
        document = await self._binary_document()
        if document is None:
            return {"available": False, "reason_code": "binary_facts_unavailable"}
        if kind == "summary":
            return cast(
                JsonObject,
                {
                    "available": True,
                    "format": document.get("format"),
                    "architecture": document.get("architecture"),
                    "packed": document.get("packed"),
                    "packer": document.get("packer"),
                    "compiler": document.get("compiler"),
                    "entry_point": document.get("entry_point"),
                    "counts": {
                        "functions": len(_as_list(document.get("functions"))),
                        "strings": len(_as_list(document.get("strings"))),
                        "imports": len(_as_list(document.get("imports"))),
                        "sections": len(_as_list(document.get("sections"))),
                        "pseudocode": len(_as_list(document.get("pseudocode"))),
                    },
                },
            )
        if kind == "obfuscation":
            return cast(
                JsonObject,
                {
                    "available": True,
                    "obfuscation": _as_list(document.get("obfuscation"))[:_MAX_FACTS_ITEMS],
                },
            )
        items = _as_list(document.get(kind))[:_MAX_FACTS_ITEMS]
        return cast(JsonObject, {"available": True, "kind": kind, "items": items})

    async def critical_logic(self) -> JsonObject:
        candidates: list[JsonObject] = []
        for ref in self._functions:
            attributes = ref.function["attributes"]
            source_attributes = attributes.get("source_attributes")
            if not isinstance(source_attributes, Mapping):
                continue
            raw = cast(Mapping[str, object], source_attributes).get("critical_logic")
            if not isinstance(raw, list):
                continue
            for item in cast(list[object], raw):
                if not isinstance(item, Mapping):
                    continue
                entry = cast(Mapping[str, object], item)
                candidates.append(
                    cast(
                        JsonObject,
                        {
                            "function_id": ref.function["id"],
                            "name": ref.function["name"],
                            "category": entry.get("category"),
                            "score": entry.get("score"),
                            "confirmed": entry.get("confirmed"),
                            "rationale": entry.get("rationale"),
                        },
                    )
                )
        return cast(JsonObject, {"candidates": candidates[: _MAX_FACTS_ITEMS]})

    async def static_leads(self) -> JsonObject:
        """Static-scanner output, presented as leads to confirm or refute."""

        async with self.database.transaction() as repositories:
            findings = await repositories.findings.list_for_task(self.task_id)
            leads: list[JsonObject] = []
            for finding in findings:
                tools = await _tool_evidence(repositories, finding)
                if not tools:
                    continue
                location = finding["location"]
                leads.append(
                    cast(
                        JsonObject,
                        {
                            "finding_id": finding["id"],
                            "cwe_id": finding["cwe_id"],
                            "title": finding["title"],
                            "severity": finding["severity"],
                            "category": finding["category"],
                            "status": finding["status"],
                            "path": location.get("path"),
                            "start_line": location.get("start_line"),
                            "address": location.get("virtual_address"),
                            "scanners": tools,
                        },
                    )
                )
        return cast(
            JsonObject,
            {
                "note": (
                    "Unverified scanner output. Each entry is a lead to confirm or "
                    "refute from code you read yourself, never a conclusion."
                ),
                "leads": leads,
            },
        )

    # -- internals ---------------------------------------------------------

    async def _resolve_function(
        self,
        *,
        function_id: str | None,
        path: str | None,
        start_line: int | None,
    ) -> AuditFunctionRef | None:
        if function_id is not None:
            return self._functions_by_id.get(function_id)
        if path is None or start_line is None:
            return None
        for ref in self._functions:
            source = ref.function["source_location"]
            if source is None or source["path"] != path:
                continue
            if source["start_line"] <= start_line <= source["end_line"]:
                return ref
        return None

    async def _function_code(self, ref: AuditFunctionRef) -> tuple[str, str, bool]:
        """Return (code, kind, truncated) for one indexed function."""

        budget = self.limits.max_text_chars
        text = pseudocode_text(ref.function, limit=budget + 1)
        if text:
            return text[:budget], "pseudocode", len(text) > budget
        source = ref.function["source_location"]
        if source is None:
            return "", "unavailable", False
        loader = self.fact_loader
        assert loader is not None
        facts = await loader.load(self.task_id, cast(JsonObject, dict(source)))
        if not facts.available or facts.excerpt is None:
            return "", "unavailable", False
        return facts.excerpt.text, "source", facts.excerpt.truncated

    async def _search_source(self, matcher: re.Pattern[str], limit: int) -> JsonObject:
        matches: list[JsonObject] = []
        scanned = 0
        for ref in self._functions:
            source = ref.function["source_location"]
            if source is None:
                continue
            text = await self._read_file(ref.version_id, source["path"])
            if text is None:
                continue
            scanned += 1
            for number, line in enumerate(text.splitlines(), start=1):
                if len(matches) >= limit:
                    break
                if matcher.search(line) is not None:
                    matches.append(
                        cast(
                            JsonObject,
                            {"path": source["path"], "line": number, "text": line.strip()[:512]},
                        )
                    )
            if len(matches) >= limit or scanned >= self.limits.max_search_files:
                break
        return cast(
            JsonObject,
            {"scope": "source", "files_scanned": scanned, "matches": matches},
        )

    async def _search_binary_strings(self, matcher: re.Pattern[str], limit: int) -> JsonObject:
        document = await self._binary_document()
        if document is None:
            return {
                "scope": "binary_strings",
                "matches": [],
                "reason_code": "binary_facts_unavailable",
            }
        matches: list[JsonObject] = []
        for item in _as_list(document.get("strings")):
            if len(matches) >= limit:
                break
            if not isinstance(item, Mapping):
                continue
            entry = cast(Mapping[str, object], item)
            value = entry.get("value")
            if not isinstance(value, str) or matcher.search(value) is None:
                continue
            matches.append(
                cast(
                    JsonObject,
                    {
                        "value": value[:512],
                        "virtual_address": entry.get("virtual_address"),
                        "file_offset": entry.get("file_offset"),
                    },
                )
            )
        return cast(JsonObject, {"scope": "binary_strings", "matches": matches})

    async def _read_file(self, version_id: str, path: str) -> str | None:
        key = (version_id, path)
        if key in self._files:
            return self._files[key]
        version = self._versions.get(version_id)
        if version is None:
            self._files[key] = None
            return None
        reader = self._reader
        if reader is None:
            reader = SourceExcerptReader(self.store)
            self._reader = reader
        try:
            text = await asyncio.to_thread(reader.read_file, version, path)
        except (SourceImportError, ArtifactStoreError, OSError):
            self._files[key] = None
            return None
        self._files[key] = text.text
        return text.text

    async def _binary_document(self) -> JsonObject | None:
        if "binary" in self._documents:
            return self._documents["binary"]
        document: JsonObject | None = None
        for version_id in self.version_ids():
            version = self._versions[version_id]
            config = version["generation_config"]
            if config.get("format") != "binary-analysis-result":
                continue
            loaded = await self._read_document(version)
            if loaded is not None:
                document = loaded
                break
        self._documents["binary"] = document
        return document

    async def _read_document(self, version: ArtifactVersion) -> JsonObject | None:
        try:
            raw = await asyncio.to_thread(self._read_bytes, version["object_ref"])
        except (ArtifactStoreError, OSError):
            return None
        if raw is None:
            return None
        try:
            loaded = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return cast(JsonObject, loaded) if isinstance(loaded, dict) else None

    def _read_bytes(self, object_ref: str) -> bytes | None:
        with self.store.open(object_ref) as source:
            return source.read()


class AuditStepExecutor:
    """Run one approved plan step against the workspace and bound its output."""

    def __init__(self, workspace: AuditWorkspace) -> None:
        self.workspace = workspace
        self.reported: list[ReportedFinding] = []

    async def execute(self, call: ScheduledToolCall) -> JsonObject:
        name = call.tool["name"]
        arguments = call.arguments
        try:
            if name == FUNCTION_LIST_TOOL:
                return await self.workspace.list_functions(
                    path_prefix=_optional_str(arguments, "path_prefix"),
                    name_pattern=_optional_str(arguments, "name_pattern"),
                    binary_only=bool(arguments.get("binary_only", False)),
                    limit=_bounded_int(arguments, "limit", 50, 1, _MAX_LIST_LIMIT),
                )
            if name == FUNCTION_READ_TOOL:
                return await self.workspace.read_function(
                    function_id=_optional_str(arguments, "function_id"),
                    path=_optional_str(arguments, "path"),
                    start_line=_optional_int(arguments, "start_line"),
                )
            if name == CODE_SEARCH_TOOL:
                return await self.workspace.search(
                    pattern=str(arguments["pattern"]),
                    scope=str(arguments.get("scope", "source")),
                    limit=_bounded_int(arguments, "limit", 50, 1, _MAX_SEARCH_LIMIT),
                )
            if name == CALL_NEIGHBORHOOD_TOOL:
                return await self.workspace.neighborhood(
                    function_id=str(arguments["function_id"]),
                    depth=_bounded_int(arguments, "depth", 1, 1, _MAX_NEIGHBORHOOD_DEPTH),
                )
            if name == ARTIFACT_FACTS_TOOL:
                return await self.workspace.artifact_facts(kind=str(arguments["kind"]))
            if name == STATIC_LEADS_TOOL:
                return await self.workspace.static_leads()
            if name == CRITICAL_LOGIC_TOOL:
                return await self.workspace.critical_logic()
            if name == FINDING_REPORT_TOOL:
                return self._report(call)
        except (ArtifactStoreError, OSError, KeyError, ValueError) as error:
            return _failed(f"{name}.tool_error", type(error).__name__)
        return _failed("audit.unknown_tool", name)

    def _report(self, call: ScheduledToolCall) -> JsonObject:
        if len(self.reported) >= _MAX_REPORTED_FINDINGS:
            return _failed("finding_report.limit_reached", str(_MAX_REPORTED_FINDINGS))
        arguments = call.arguments
        address = _optional_int(arguments, "address")
        request = _optional_str(arguments, "verification_request")
        self.reported.append(
            ReportedFinding(
                cwe_id=str(arguments["cwe_id"]),
                title=str(arguments["title"]),
                severity=str(arguments["severity"]),
                rationale=str(arguments["rationale"]),
                path=_optional_str(arguments, "path"),
                start_line=_optional_int(arguments, "start_line"),
                end_line=_optional_int(arguments, "end_line"),
                address=address,
                verification_request=None if request in (None, "none") else request,
                verification_reason=_optional_str(arguments, "verification_reason"),
                step_id=call.step_id,
            )
        )
        return {"recorded": True, "total": len(self.reported)}


async def _tool_evidence(repositories: Repositories, finding: Finding) -> list[str]:
    """Which scanners contributed TOOL_OUTPUT evidence to this finding."""

    relations = await repositories.findings.list_evidence_relations(finding["id"])
    names: list[str] = []
    for relation in relations:
        evidence = await repositories.evidence.get(relation["evidence_id"])
        if evidence["type"] is not EvidenceType.TOOL_OUTPUT:
            continue
        tool = evidence["tool"]
        name = tool["name"] if tool else "unknown"
        if name not in names:
            names.append(name)
    return names


def _function_summary(ref: AuditFunctionRef) -> JsonObject:
    function = ref.function
    source = function["source_location"]
    return cast(
        JsonObject,
        {
            "function_id": function["id"],
            "name": function["name"],
            "language": function["language"],
            "path": source["path"] if source else None,
            "start_line": source["start_line"] if source else None,
            "address": binary_address_of(function),
        },
    )


def _related_summary(function: PairFunction) -> JsonObject:
    source = function["source_location"]
    return cast(
        JsonObject,
        {
            "function_id": function["id"],
            "name": function["name"],
            "path": source["path"] if source else None,
            "start_line": source["start_line"] if source else None,
            "address": binary_address_of(function),
        },
    )


def _function_sort_key(ref: AuditFunctionRef) -> tuple[str, int, str]:
    source = ref.function["source_location"]
    return (
        source["path"] if source else "",
        source["start_line"] if source else 0,
        ref.function["name"],
    )


def _as_list(value: JsonValue | object) -> list[JsonValue]:
    if isinstance(value, list):
        return cast(list[JsonValue], value)
    return []


def _compile(pattern: str | None) -> re.Pattern[str] | None:
    if not pattern:
        return None
    try:
        return re.compile(pattern)
    except re.error:
        return None


def _optional_str(arguments: Mapping[str, JsonValue], key: str) -> str | None:
    value = arguments.get(key)
    return value if isinstance(value, str) and value else None


def _optional_int(arguments: Mapping[str, JsonValue], key: str) -> int | None:
    value = arguments.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _bounded_int(
    arguments: Mapping[str, JsonValue], key: str, default: int, low: int, high: int
) -> int:
    value = _optional_int(arguments, key)
    if value is None:
        return default
    return max(low, min(high, value))


def _failed(code: str, detail: str) -> JsonObject:
    return {"failed": True, "reason_code": code, "detail": detail}


__all__ = [
    "ARTIFACT_FACTS_TOOL",
    "AUDIT_TOOLS",
    "CALL_NEIGHBORHOOD_TOOL",
    "CODE_SEARCH_TOOL",
    "CRITICAL_LOGIC_TOOL",
    "FINDING_REPORT_TOOL",
    "FUNCTION_LIST_TOOL",
    "FUNCTION_READ_TOOL",
    "IN_PROCESS_DIGEST",
    "STATIC_LEADS_TOOL",
    "AuditFunctionRef",
    "AuditStepExecutor",
    "AuditWorkspace",
    "AuditWorkspaceLimits",
    "ReportedFinding",
]
