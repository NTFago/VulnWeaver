"""Function and call indexing for C, C++, Python, and Java source trees."""

from __future__ import annotations

import hashlib
from collections.abc import Generator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import tree_sitter_c
import tree_sitter_cpp
import tree_sitter_java
import tree_sitter_python
from tree_sitter import Language, Node, Parser
from vulnweaver_contracts import (
    Capability,
    CapabilityProfile,
    CapabilityStatus,
    SchemaVersion,
    SourceCall,
    SourceFileRecord,
    SourceFunction,
    SourceImportResult,
    SourceLocation,
    SourceParameter,
    validate_contract,
)


@dataclass(frozen=True, slots=True)
class SourceIndexerSettings:
    max_files: int = 20_000
    max_parse_bytes: int = 8 * 1024 * 1024
    max_functions: int = 500_000
    max_calls: int = 2_000_000

    def __post_init__(self) -> None:
        if self.max_files < 1 or self.max_files > 1_000_000:
            raise ValueError("source index file limit is outside the safe range")
        if self.max_parse_bytes < 1024 or self.max_parse_bytes > 256 * 1024 * 1024:
            raise ValueError("source parse byte limit is outside the safe range")
        if self.max_functions < 1 or self.max_calls < 1:
            raise ValueError("source index entity limits must be positive")


@dataclass(frozen=True, slots=True)
class _LanguageConfig:
    language: str
    parser: Parser
    function_types: frozenset[str]
    call_types: frozenset[str]
    class_types: frozenset[str]


_EXTENSIONS: dict[str, str] = {
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hh": "cpp",
    ".hpp": "cpp",
    ".hxx": "cpp",
    ".py": "python",
    ".pyi": "python",
    ".java": "java",
}

_BUILD_FILES: dict[str, str] = {
    "cmakelists.txt": "cmake",
    "makefile": "make",
    "meson.build": "meson",
    "configure.ac": "autotools",
    "pyproject.toml": "python-pyproject",
    "setup.py": "python-setuptools",
    "requirements.txt": "python-requirements",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
}


class SourceIndexer:
    def __init__(self, settings: SourceIndexerSettings | None = None) -> None:
        self._settings = settings or SourceIndexerSettings()

    def index(
        self,
        root: str | Path,
        artifact_version_id: str,
        *,
        created_at: str | None = None,
    ) -> SourceImportResult:
        source_root = Path(root)
        if not source_root.is_dir():
            raise ValueError("source index root must be a directory")
        files: list[SourceFileRecord] = []
        functions: list[SourceFunction] = []
        calls: list[SourceCall] = []
        languages: set[str] = set()
        build_systems: set[str] = set()
        parse_errors: dict[str, int] = {}
        languages_config = _language_configs()

        paths = sorted(path for path in source_root.rglob("*") if path.is_file())
        if len(paths) > self._settings.max_files:
            raise ValueError("source tree file-count limit exceeded")
        for path in paths:
            if path.is_symlink():
                raise ValueError("source tree unexpectedly contains a symbolic link")
            relative = path.relative_to(source_root).as_posix()
            if ".git" in {part.casefold() for part in path.relative_to(source_root).parts}:
                continue
            build_system = _BUILD_FILES.get(path.name.casefold())
            if build_system is not None:
                build_systems.add(build_system)
            language = _EXTENSIONS.get(path.suffix.casefold())
            data = path.read_bytes()
            digest = "sha256:" + hashlib.sha256(data).hexdigest()
            if _looks_binary(data):
                files.append(_file_record(relative, len(data), digest, language, "binary"))
                continue
            if language is None:
                files.append(_file_record(relative, len(data), digest, None, "unsupported"))
                continue
            languages.add(language)
            if len(data) > self._settings.max_parse_bytes:
                files.append(_file_record(relative, len(data), digest, language, "too_large"))
                continue
            config = languages_config[language]
            tree = config.parser.parse(data)
            status: Literal["indexed", "parse_error"] = (
                "parse_error" if tree.root_node.has_error else "indexed"
            )
            if status == "parse_error":
                parse_errors[language] = parse_errors.get(language, 0) + 1
            files.append(_file_record(relative, len(data), digest, language, status))
            indexed_functions, indexed_calls = self._index_tree(
                config,
                tree.root_node,
                data,
                relative,
                artifact_version_id,
            )
            functions.extend(indexed_functions)
            calls.extend(indexed_calls)
            if len(functions) > self._settings.max_functions:
                raise ValueError("source function-count limit exceeded")
            if len(calls) > self._settings.max_calls:
                raise ValueError("source call-count limit exceeded")

        timestamp = created_at or datetime.now(UTC).isoformat().replace("+00:00", "Z")
        profile = _capability_profile(
            artifact_version_id,
            languages,
            build_systems,
            parse_errors,
            timestamp,
        )
        result = SourceImportResult(
            schema_version=SchemaVersion.VALUE_1_0_0,
            artifact_version_id=artifact_version_id,
            files=files,
            functions=functions,
            calls=calls,
            capability_profile=profile,
        )
        validate_contract("SourceImportResult", result)
        return result

    def _index_tree(
        self,
        config: _LanguageConfig,
        root: Node,
        source: bytes,
        path: str,
        artifact_version_id: str,
    ) -> tuple[list[SourceFunction], list[SourceCall]]:
        functions: list[SourceFunction] = []
        calls: list[SourceCall] = []
        for node in _walk(root):
            if node.type not in config.function_types:
                continue
            function = _source_function(config, node, source, path, artifact_version_id)
            if function is None:
                continue
            functions.append(function)
            calls.extend(
                _calls_in_function(
                    config,
                    node,
                    source,
                    path,
                    artifact_version_id,
                    function["id"],
                )
            )
        return functions, calls


def _config(
    name: str,
    capsule: object,
    function_types: set[str],
    call_types: set[str],
    class_types: set[str],
) -> _LanguageConfig:
    language = Language(capsule)
    return _LanguageConfig(
        name,
        Parser(language),
        frozenset(function_types),
        frozenset(call_types),
        frozenset(class_types),
    )


def _language_configs() -> dict[str, _LanguageConfig]:
    # Parser instances are scoped to one index operation because one executor can
    # serve multiple jobs concurrently in separate worker threads.
    return {
        "c": _config(
            "c",
            tree_sitter_c.language(),
            {"function_definition"},
            {"call_expression"},
            {"struct_specifier", "union_specifier"},
        ),
        "cpp": _config(
            "cpp",
            tree_sitter_cpp.language(),
            {"function_definition"},
            {"call_expression"},
            {"class_specifier", "struct_specifier", "namespace_definition"},
        ),
        "python": _config(
            "python",
            tree_sitter_python.language(),
            {"function_definition"},
            {"call"},
            {"class_definition"},
        ),
        "java": _config(
            "java",
            tree_sitter_java.language(),
            {"method_declaration", "constructor_declaration"},
            {"method_invocation", "object_creation_expression"},
            {"class_declaration", "interface_declaration", "enum_declaration"},
        ),
    }


def _source_function(
    config: _LanguageConfig,
    node: Node,
    source: bytes,
    path: str,
    artifact_version_id: str,
) -> SourceFunction | None:
    name_node = node.child_by_field_name("name")
    if name_node is None:
        declarator = node.child_by_field_name("declarator")
        name_node = _declarator_identifier(declarator)
    if name_node is None:
        name_node = _declarator_identifier(node)
    if name_node is None:
        return None
    name = _node_text(name_node, source).strip()
    if not name:
        return None
    scopes = _scope_names(config, node, source)
    qualified = ".".join([*scopes, name]) if scopes else name
    kind: Literal["function", "method", "constructor"] = "function"
    if node.type == "constructor_declaration":
        kind = "constructor"
    elif scopes:
        kind = "method"
    location = _location(node, artifact_version_id, path)
    identifier = _stable_identifier(
        "function",
        artifact_version_id,
        path,
        str(location["start_line"]),
        str(location["start_column"]),
        qualified,
    )
    return SourceFunction(
        id=identifier,
        name=name[:512],
        qualified_name=qualified[:2048],
        kind=kind,
        language=config.language,
        parameters=_parameters(node, source),
        location=location,
    )


def _parameters(node: Node, source: bytes) -> list[SourceParameter]:
    parameter_node = node.child_by_field_name("parameters")
    if parameter_node is None:
        parameter_node = _first_descendant(
            node, {"parameter_list", "formal_parameters", "parameters"}
        )
    if parameter_node is None:
        return []
    parameters: list[SourceParameter] = []
    for child in parameter_node.named_children:
        if child.type in {"identifier", "self", "typed_parameter", "default_parameter"}:
            name_node = child if child.type == "identifier" else _last_identifier(child)
        else:
            name_node = child.child_by_field_name("name") or _last_identifier(child)
        if name_node is None:
            continue
        name = _node_text(name_node, source).strip()
        if not name:
            continue
        type_node = child.child_by_field_name("type")
        type_text = _node_text(type_node, source).strip() if type_node is not None else None
        parameters.append(
            SourceParameter(
                name=name[:512],
                type=type_text[:1024] if type_text else None,
            )
        )
    return parameters


def _scope_names(config: _LanguageConfig, node: Node, source: bytes) -> list[str]:
    result: list[str] = []
    parent = node.parent
    while parent is not None:
        if parent.type in config.class_types or parent.type in config.function_types:
            name_node = parent.child_by_field_name("name")
            if name_node is None and parent.type in config.function_types:
                declarator = parent.child_by_field_name("declarator")
                name_node = _declarator_identifier(declarator)
            if name_node is not None:
                value = _node_text(name_node, source).strip()
                if value:
                    result.append(value[:512])
        parent = parent.parent
    result.reverse()
    return result


def _calls_in_function(
    config: _LanguageConfig,
    function_node: Node,
    source: bytes,
    path: str,
    artifact_version_id: str,
    function_id: str,
) -> list[SourceCall]:
    result: list[SourceCall] = []
    stack = list(reversed(function_node.named_children))
    while stack:
        node = stack.pop()
        if node.type in config.function_types:
            continue
        if node.type in config.call_types:
            callee_node = (
                node.child_by_field_name("function")
                or node.child_by_field_name("name")
                or node.child_by_field_name("type")
            )
            if callee_node is not None:
                callee = _node_text(callee_node, source).strip()
                if callee:
                    result.append(
                        SourceCall(
                            caller_id=function_id,
                            callee=callee[:2048],
                            location=_location(node, artifact_version_id, path),
                        )
                    )
        stack.extend(reversed(node.named_children))
    return result


def _walk(root: Node) -> Generator[Node, None, None]:
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.named_children))


def _first_descendant(node: Node, types: set[str]) -> Node | None:
    for candidate in _walk(node):
        if candidate is not node and candidate.type in types:
            return candidate
    return None


def _declarator_identifier(node: Node | None) -> Node | None:
    if node is None:
        return None
    if node.type in {
        "identifier",
        "field_identifier",
        "type_identifier",
        "operator_name",
        "destructor_name",
    }:
        return node
    nested = node.child_by_field_name("declarator")
    if nested is not None:
        candidate = _declarator_identifier(nested)
        if candidate is not None:
            return candidate
    for child in node.named_children:
        if child.type in {"parameter_list", "parameters", "formal_parameters"}:
            continue
        candidate = _declarator_identifier(child)
        if candidate is not None:
            return candidate
    return None


def _last_identifier(node: Node | None) -> Node | None:
    if node is None:
        return None
    candidate: Node | None = None
    for descendant in _walk(node):
        if descendant.type in {
            "identifier",
            "field_identifier",
            "type_identifier",
            "operator_name",
            "destructor_name",
        }:
            candidate = descendant
    return candidate


def _node_text(node: Node, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _location(node: Node, artifact_version_id: str, path: str) -> SourceLocation:
    return SourceLocation(
        artifact_version_id=artifact_version_id,
        path=path,
        start_line=node.start_point.row + 1,
        start_column=node.start_point.column + 1,
        end_line=node.end_point.row + 1,
        end_column=node.end_point.column + 1,
    )


def _file_record(
    path: str,
    size: int,
    digest: str,
    language: str | None,
    status: Literal["indexed", "unsupported", "binary", "too_large", "parse_error"],
) -> SourceFileRecord:
    return SourceFileRecord(
        path=path,
        size_bytes=size,
        digest=digest,
        language=language,
        parse_status=status,
    )


def _capability_profile(
    artifact_version_id: str,
    languages: set[str],
    build_systems: set[str],
    parse_errors: dict[str, int],
    created_at: str,
) -> CapabilityProfile:
    capabilities: list[Capability] = [
        Capability(
            name="source_manifest",
            status=CapabilityStatus.AVAILABLE,
            tool_name="source-import",
            reason=None,
        )
    ]
    for language in ("c", "cpp", "python", "java"):
        if language in languages:
            errors = parse_errors.get(language, 0)
            capabilities.append(
                Capability(
                    name=f"tree_sitter_{language}",
                    status=(CapabilityStatus.UNAVAILABLE if errors else CapabilityStatus.AVAILABLE),
                    tool_name="source-import",
                    reason=(f"parse_errors:{errors}" if errors else None),
                )
            )
        else:
            capabilities.append(
                Capability(
                    name=f"tree_sitter_{language}",
                    status=CapabilityStatus.UNAVAILABLE,
                    tool_name=None,
                    reason="language_not_detected",
                )
            )
    return CapabilityProfile(
        schema_version=SchemaVersion.VALUE_1_0_0,
        artifact_version_id=artifact_version_id,
        languages=sorted(languages),
        architectures=[],
        build_systems=sorted(build_systems),
        capabilities=capabilities,
        created_at=created_at,
    )


def _looks_binary(data: bytes) -> bool:
    sample = data[:8192]
    return b"\x00" in sample


def _stable_identifier(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()[:32]
    return f"{prefix}:{digest}"
