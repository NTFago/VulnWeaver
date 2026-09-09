"""Runtime helpers for validating data at trust boundaries."""

from __future__ import annotations

import json
import math
from collections.abc import Callable, Iterable, Mapping
from functools import lru_cache
from importlib.resources import files
from typing import Any, cast

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

from vulnweaver_contracts.generated import SCHEMA_VERSION


class ContractValidationError(ValueError):
    """Raised when a payload does not satisfy a named public contract."""

    def __init__(self, definition: str, errors: list[str]) -> None:
        self.definition = definition
        self.errors = tuple(errors)
        super().__init__(f"{definition} validation failed: {'; '.join(errors)}")


@lru_cache(maxsize=1)
def _bundle() -> dict[str, Any]:
    schema_path = files("vulnweaver_contracts").joinpath("schemas", "v1", "contracts.schema.json")
    return cast(dict[str, Any], json.loads(schema_path.read_text(encoding="utf-8")))


def get_contract_schema(definition: str) -> dict[str, Any]:
    """Return a self-contained schema rooted at one named definition."""

    bundle = _bundle()
    definitions = bundle["$defs"]
    if definition not in definitions:
        raise KeyError(f"unknown contract definition: {definition}")
    return {
        "$schema": bundle["$schema"],
        "$id": f"{bundle['$id']}#{definition}",
        "$defs": definitions,
        "$ref": f"#/$defs/{definition}",
    }


def validate_contract(definition: str, payload: Mapping[str, object]) -> None:
    """Validate a mapping and report every deterministic validation failure."""

    non_finite_paths = _non_finite_number_paths(payload)
    if non_finite_paths:
        raise ContractValidationError(
            definition,
            [f"{path}: non-finite numbers are not valid JSON" for path in non_finite_paths],
        )
    validator = Draft202012Validator(
        get_contract_schema(definition), format_checker=FormatChecker()
    )
    iter_errors = cast(
        Callable[[object], Iterable[ValidationError]],
        validator.iter_errors,  # pyright: ignore[reportUnknownMemberType]
    )
    failures = sorted(iter_errors(payload), key=_validation_error_key)
    if failures:
        raise ContractValidationError(
            definition,
            [f"{_json_path(error)}: {error.message}" for error in failures],
        )


def ensure_supported_version(version: str) -> None:
    """Accept the frozen v1 contract and reject unknown major/minor payloads."""

    if version != SCHEMA_VERSION:
        raise ContractValidationError(
            "SchemaVersion",
            [f"$: unsupported version {version!r}; expected {SCHEMA_VERSION!r}"],
        )


def _validation_error_key(error: ValidationError) -> tuple[str, str]:
    return (_json_path(error), error.message)


def _json_path(error: ValidationError) -> str:
    parts = [str(part) for part in error.absolute_path]
    return "$" if not parts else "$." + ".".join(parts)


def _non_finite_number_paths(value: object, path: str = "$") -> list[str]:
    if isinstance(value, float) and not math.isfinite(value):
        return [path]
    if isinstance(value, Mapping):
        mapping = cast(Mapping[object, object], value)
        failures: list[str] = []
        for key, nested in mapping.items():
            failures.extend(_non_finite_number_paths(nested, f"{path}.{key}"))
        return failures
    if isinstance(value, (list, tuple)):
        values = cast(list[object] | tuple[object, ...], value)
        failures = []
        for index, nested in enumerate(values):
            failures.extend(_non_finite_number_paths(nested, f"{path}.{index}"))
        return failures
    return []
