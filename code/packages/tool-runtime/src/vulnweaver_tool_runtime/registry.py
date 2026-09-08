"""Immutable, exact-version ToolSpec registry and JSON loaders."""

from __future__ import annotations

import copy
import json
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import cast

from jsonschema import Draft202012Validator, SchemaError
from vulnweaver_contracts import ToolSpec, ensure_supported_version, validate_contract

from vulnweaver_tool_runtime.errors import ToolNotFound, ToolRegistrationConflict, ToolSpecError


class ToolRegistry:
    """In-memory registry whose entries are immutable after registration.

    Tool identity is the exact ``name`` + ``version`` pair.  There is no implicit
    latest-version lookup: a plan must pin the version and image digest supplied
    by the registered ToolSpec.
    """

    def __init__(self, specs: Iterable[Mapping[str, object]] = ()) -> None:
        self._specs: dict[tuple[str, str], ToolSpec] = {}
        for spec in specs:
            self.register(spec)

    def register(self, value: Mapping[str, object]) -> ToolSpec:
        spec = _validated_spec(value)
        key = (spec["name"], spec["version"])
        existing = self._specs.get(key)
        if existing is not None:
            if existing == spec:
                return copy.deepcopy(existing)
            raise ToolRegistrationConflict(
                "a different ToolSpec is already registered for this version",
                details={"name": spec["name"], "version": spec["version"]},
            )
        self._specs[key] = copy.deepcopy(spec)
        return copy.deepcopy(spec)

    def get(self, name: str, version: str) -> ToolSpec:
        spec = self._specs.get((name, version))
        if spec is None:
            raise ToolNotFound(
                "the exact tool name and version are not registered",
                details={"name": name, "version": version},
            )
        return copy.deepcopy(spec)

    def resolve(self, name: str, version: str) -> ToolSpec:
        """Alias emphasizing that resolution is always exact-version."""

        return self.get(name, version)

    def snapshot(self) -> tuple[ToolSpec, ...]:
        """Return a deterministic, detached registry snapshot."""

        return tuple(copy.deepcopy(self._specs[key]) for key in sorted(self._specs))

    def __len__(self) -> int:
        return len(self._specs)


def _validated_spec(value: Mapping[str, object]) -> ToolSpec:
    candidate = cast(ToolSpec, copy.deepcopy(dict(value)))
    try:
        validate_contract("ToolSpec", candidate)
        ensure_supported_version(str(candidate["schema_version"]))
        Draft202012Validator.check_schema(candidate["command_schema"])
        Draft202012Validator.check_schema(candidate["output_schema"])
    except (TypeError, SchemaError, ValueError) as error:
        raise ToolSpecError("ToolSpec failed structural validation") from error
    return candidate


class ToolSpecLoader:
    """Load trusted, versioned ToolSpec documents without executing their content."""

    @staticmethod
    def from_mapping(value: Mapping[str, object]) -> ToolSpec:
        return _validated_spec(value)

    @staticmethod
    def from_json_file(path: str | Path) -> tuple[ToolSpec, ...]:
        file_path = Path(path)
        try:
            raw: object = json.loads(file_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ToolSpecError(
                "unable to read ToolSpec JSON",
                details={"path": str(file_path)},
            ) from error
        return ToolSpecLoader.from_document(raw, source=str(file_path))

    @staticmethod
    def from_document(value: object, *, source: str = "document") -> tuple[ToolSpec, ...]:
        if isinstance(value, Mapping):
            return (ToolSpecLoader.from_mapping(cast(Mapping[str, object], value)),)
        if isinstance(value, list):
            specs: list[ToolSpec] = []
            items = cast(list[object], value)
            for index, item in enumerate(items):
                if not isinstance(item, Mapping):
                    raise ToolSpecError(
                        "ToolSpec collection contains a non-object",
                        details={"source": source, "index": index},
                    )
                specs.append(ToolSpecLoader.from_mapping(cast(Mapping[str, object], item)))
            return tuple(specs)
        raise ToolSpecError(
            "ToolSpec document must be an object or an array of objects",
            details={"source": source},
        )

    @staticmethod
    def load_directory(directory: str | Path) -> ToolRegistry:
        root = Path(directory)
        if not root.is_dir():
            raise ToolSpecError("ToolSpec directory does not exist", details={"path": str(root)})
        registry = ToolRegistry()
        for path in sorted(root.glob("*.json")):
            for spec in ToolSpecLoader.from_json_file(path):
                registry.register(spec)
        return registry
