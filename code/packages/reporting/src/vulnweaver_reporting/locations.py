"""Format canonical Finding locations for report consumers."""

from __future__ import annotations

from collections.abc import Mapping


def location_text(location: Mapping[str, object]) -> str:
    """Return a bounded human-readable source range or binary address."""
    address = binary_address(location)
    if isinstance(address, int):
        return f"0x{address:x}"
    path = location.get("path")
    if not isinstance(path, str) or not path:
        return "unknown"
    start_line, end_line = source_line_range(location)
    line_text = str(start_line) if start_line == end_line else f"{start_line}-{end_line}"
    return f"{path[:4096]}:{line_text}"


def source_region(location: Mapping[str, object]) -> dict[str, int]:
    """Build a SARIF source region from a canonical or legacy location."""
    if not isinstance(location.get("path"), str) or not location["path"]:
        return {}
    start_line, end_line = source_line_range(location)
    region = {"startLine": start_line, "endLine": end_line}
    start_column = location.get("start_column")
    end_column = location.get("end_column")
    if isinstance(start_column, int) and start_column > 0:
        region["startColumn"] = start_column
    if isinstance(end_column, int) and end_column > 0:
        region["endColumn"] = end_column
    return region


def source_line_range(location: Mapping[str, object]) -> tuple[int, int]:
    """Read the v1 SourceLocation range, with a legacy ``line`` fallback."""
    start_line = _positive_int(location.get("start_line"))
    if start_line is None:
        start_line = _positive_int(location.get("line")) or 1
    end_line = _positive_int(location.get("end_line")) or start_line
    return start_line, max(start_line, end_line)


def binary_address(location: Mapping[str, object]) -> int | None:
    """Read the canonical binary address, with a legacy key fallback."""
    virtual_address = location.get("virtual_address")
    if isinstance(virtual_address, int):
        return virtual_address
    address = location.get("address")
    return address if isinstance(address, int) else None


def _positive_int(value: object) -> int | None:
    return value if isinstance(value, int) and value > 0 else None
