"""Generate Python and TypeScript views from the canonical JSON Schema bundle."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, cast

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = (
    PACKAGE_ROOT / "src" / "vulnweaver_contracts" / "schemas" / "v1" / "contracts.schema.json"
)
PYTHON_OUTPUT = PACKAGE_ROOT / "src" / "vulnweaver_contracts" / "generated.py"
TYPESCRIPT_OUTPUT = PACKAGE_ROOT / "typescript" / "index.ts"


def _definition_name(reference: str) -> str:
    prefix = "#/$defs/"
    if not reference.startswith(prefix):
        raise ValueError(f"unsupported external reference: {reference}")
    return reference.removeprefix(prefix)


def _python_type(schema: dict[str, Any]) -> str:
    if "$ref" in schema:
        return _definition_name(schema["$ref"])
    if "const" in schema:
        return f"Literal[{schema['const']!r}]"
    if "enum" in schema:
        values = ", ".join(repr(value) for value in schema["enum"])
        return f"Literal[{values}]"
    union = cast(list[dict[str, Any]] | None, schema.get("oneOf") or schema.get("anyOf"))
    if union:
        return " | ".join(_python_type(option) for option in union)
    schema_type = cast(str | list[str] | None, schema.get("type"))
    if isinstance(schema_type, list):
        return " | ".join(_python_type({"type": item}) for item in schema_type)
    if schema_type == "string":
        return "str"
    if schema_type == "integer":
        return "int"
    if schema_type == "number":
        return "float"
    if schema_type == "boolean":
        return "bool"
    if schema_type == "null":
        return "None"
    if schema_type == "array":
        return f"list[{_python_type(schema.get('items', {}))}]"
    if schema_type == "object":
        value_schema = schema.get("additionalProperties")
        if isinstance(value_schema, dict):
            additional = cast(dict[str, Any], value_schema)
            return f"dict[str, {_python_type(additional)}]"
        return "dict[str, JsonValue]"
    return "JsonValue"


def _typescript_type(schema: dict[str, Any]) -> str:
    if "$ref" in schema:
        return _definition_name(schema["$ref"])
    if "const" in schema:
        return json.dumps(schema["const"])
    if "enum" in schema:
        return " | ".join(json.dumps(value) for value in schema["enum"])
    union = cast(list[dict[str, Any]] | None, schema.get("oneOf") or schema.get("anyOf"))
    if union:
        return " | ".join(_typescript_type(option) for option in union)
    schema_type = cast(str | list[str] | None, schema.get("type"))
    if isinstance(schema_type, list):
        return " | ".join(_typescript_type({"type": item}) for item in schema_type)
    if schema_type == "string":
        return "string"
    if schema_type in {"integer", "number"}:
        return "number"
    if schema_type == "boolean":
        return "boolean"
    if schema_type == "null":
        return "null"
    if schema_type == "array":
        return f"Array<{_typescript_type(schema.get('items', {}))}>"
    if schema_type == "object":
        value_schema = schema.get("additionalProperties")
        if isinstance(value_schema, dict):
            additional = cast(dict[str, Any], value_schema)
            return f"Record<string, {_typescript_type(additional)}>"
        return "Record<string, JsonValue>"
    return "JsonValue"


def _enum_member(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").upper()
    if normalized[:1].isdigit():
        normalized = f"VALUE_{normalized}"
    return normalized


def render_python(bundle: dict[str, Any]) -> str:
    definitions: dict[str, dict[str, Any]] = bundle["$defs"]
    lines = [
        '"""Generated from schemas/v1/contracts.schema.json; do not edit."""',
        "",
        "from __future__ import annotations",
        "",
        "from enum import StrEnum",
        "from typing import Literal, NotRequired, TypedDict",
        "",
        'SCHEMA_VERSION = "1.0.0"',
        (
            "type JsonValue = None | bool | int | float | str | "
            "list[JsonValue] | dict[str, JsonValue]"
        ),
        "",
    ]
    enums = {
        name: schema
        for name, schema in definitions.items()
        if schema.get("type") == "string" and "enum" in schema
    }
    for name, schema in enums.items():
        lines.append(f"class {name}(StrEnum):")
        for value in schema["enum"]:
            lines.append(f"    {_enum_member(value)} = {value!r}")
        lines.append("")

    for name, schema in definitions.items():
        if name in enums:
            continue
        if schema.get("type") == "object" and "properties" in schema:
            lines.append(f"class {name}(TypedDict):")
            required = set(schema.get("required", []))
            for property_name, property_schema in schema["properties"].items():
                annotation = _python_type(property_schema)
                if property_name not in required:
                    annotation = f"NotRequired[{annotation}]"
                lines.append(f"    {property_name}: {annotation}")
            lines.append("")
        else:
            lines.append(f"type {name} = {_python_type(schema)}")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_typescript(bundle: dict[str, Any]) -> str:
    definitions: dict[str, dict[str, Any]] = bundle["$defs"]
    lines = [
        "// Generated from schemas/v1/contracts.schema.json; do not edit.",
        "",
        'export const SCHEMA_VERSION = "1.0.0" as const;',
        (
            "export type JsonValue = null | boolean | number | string | "
            "JsonValue[] | { [key: string]: JsonValue };"
        ),
        "",
    ]
    for name, schema in definitions.items():
        if schema.get("type") == "object" and "properties" in schema:
            lines.append(f"export interface {name} {{")
            required = set(schema.get("required", []))
            for property_name, property_schema in schema["properties"].items():
                optional = "" if property_name in required else "?"
                lines.append(f"  {property_name}{optional}: {_typescript_type(property_schema)};")
            lines.append("}")
        else:
            lines.append(f"export type {name} = {_typescript_type(schema)};")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _update(path: Path, content: str, check: bool) -> bool:
    current = path.read_text(encoding="utf-8") if path.exists() else None
    if current == content:
        return False
    if not check:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail when generated files drift")
    args = parser.parse_args()
    bundle = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    changed = [
        path
        for path, content in (
            (PYTHON_OUTPUT, render_python(bundle)),
            (TYPESCRIPT_OUTPUT, render_typescript(bundle)),
        )
        if _update(path, content, args.check)
    ]
    if args.check and changed:
        for path in changed:
            print(f"generated contract is stale: {path.relative_to(PACKAGE_ROOT)}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
