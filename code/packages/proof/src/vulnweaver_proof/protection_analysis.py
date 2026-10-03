"""Deterministic protection enumeration over the digest-bound target (CR-04).

The injection ``FindingPolicy`` requires a ``protection_analysis`` fact. This
module is its independent source: a pure-AST enumerator, owned by the control
plane, that walks the bound callable and its module-local callees in the exact
source bytes the sandbox executed and lists the protection-relevant constructs
it sees — dangerous sinks, input validation, exception guards, sanitizers and
safe alternatives.

It is deliberately *not* a taint analysis and not a completeness claim: the
lexicon below is a bounded v1, the enumeration is advisory, and interpreting
the result stays with the reviewer. What it establishes mechanically is that a
typed protection enumeration ran against the registered sample and produced a
stable, reproducible result — which is exactly what the policy fact means.
"""

from __future__ import annotations

import ast
import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from vulnweaver_contracts import JsonObject

MAX_SCAN_BYTES = 512 * 1024
MAX_CLOSURE_FUNCTIONS = 32
MAX_CLOSURE_DEPTH = 4
MAX_ENTRIES = 32
MAX_ENTRY_CHARS = 128

# Calls whose name alone marks a dangerous sink (Name and Attribute calls).
_SINK_NAMES = frozenset({"eval", "exec", "compile", "__import__"})
# Attribute calls flagged only for the owning modules that make them dangerous;
# this is what keeps json.loads out of the pickle.loads shape.
_SINK_ATTRIBUTES = frozenset({"system", "popen"})
_SINK_OWNED = {("pickle", "loads"), ("yaml", "load"), ("dill", "loads")}

# Constructs that indicate input handling care on the path, matched on the
# called name (bare Name or last attribute segment).
_PROTECTION_CALLS = {
    "isinstance": "input_validation",
    "re_match": "input_validation",
    "literal_eval": "safe_alternative",
    "escape": "sanitizer",
    "quote": "sanitizer",
    "sanitize": "sanitizer",
}


@dataclass(frozen=True, slots=True)
class ProtectionScan:
    """Bounded, deterministic result of one protection enumeration."""

    sink: str
    entries: tuple[str, ...]
    functions_scanned: int
    source_digest: str

    def marker(self) -> list[str]:
        """The ``protections_observed`` marker list; never empty on success."""

        return list(self.entries)[:MAX_ENTRIES]

    def document(self) -> JsonObject:
        return cast(
            JsonObject,
            {
                "sink": self.sink,
                "protections_observed": self.marker(),
                "functions_scanned": self.functions_scanned,
                "source_digest": self.source_digest,
            },
        )


def scan_target_protections(
    source: bytes, target_callable: str
) -> ProtectionScan | None:
    """Enumerate protection-relevant constructs around the bound callable.

    Returns ``None`` when the scan cannot run honestly: the source is not
    parseable UTF-8 Python, the callable cannot be resolved in the module AST,
    or the input exceeds the scan bound. A successful scan always yields at
    least one entry (the sink itself).
    """

    if len(source) > MAX_SCAN_BYTES:
        return None
    parts = target_callable.split(".")
    if not parts or any(not part.isidentifier() for part in parts):
        return None
    try:
        tree = ast.parse(source.decode("utf-8"))
    except (SyntaxError, ValueError, UnicodeDecodeError):
        return None

    functions = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    sink_name = parts[-1]
    sink = functions.get(sink_name)
    if sink is None:
        return None

    # Module-local callee closure starting at the sink: the code the crafted
    # input can reach without leaving the bound file.
    selected: dict[str, ast.AST] = {sink_name: sink}
    frontier = [sink_name]
    depth = 0
    while frontier and depth < MAX_CLOSURE_DEPTH and len(selected) < MAX_CLOSURE_FUNCTIONS:
        next_frontier: list[str] = []
        for name in frontier:
            node = selected.get(name)
            if node is None:
                continue
            for callee in _local_callees(node, functions):
                if callee not in selected and len(selected) < MAX_CLOSURE_FUNCTIONS:
                    selected[callee] = functions[callee]
                    next_frontier.append(callee)
        frontier = next_frontier
        depth += 1

    entries: set[str] = set()
    for name, node in sorted(selected.items()):
        entries.update(_scan_function(name, node))
    # The bound callable itself resolved in the AST: always record the anchor,
    # so a scan over a clean function still documents what was enumerated.
    entries.add(_entry(f"callable_resolved:{sink_name}", sink_name, sink.lineno, False))
    ordered = tuple(sorted(entries)[:MAX_ENTRIES])
    if not ordered:
        # Unreachable given the anchor entry above; kept as an honest guard so
        # the scan can never claim with an empty enumeration.
        return None
    digest = "sha256:" + hashlib.sha256(source).hexdigest()
    return ProtectionScan(
        sink=f"{target_callable}@{sink.lineno}",
        entries=ordered,
        functions_scanned=len(selected),
        source_digest=digest,
    )


def _local_callees(node: ast.AST, functions: Mapping[str, ast.AST]) -> list[str]:
    callees: list[str] = []
    for call in ast.walk(node):
        if (
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
            and call.func.id in functions
            and call.func.id not in callees
        ):
            callees.append(call.func.id)
    return callees


def _scan_function(name: str, node: ast.AST) -> set[str]:
    """Collect bounded, stable entries for one function in the closure."""

    entries: set[str] = set()
    guards: list[tuple[int, int]] = []  # (lineno, end_lineno) of try blocks
    for outer in ast.walk(node):
        if isinstance(outer, ast.Try):
            guards.append((outer.lineno, getattr(outer, "end_lineno", outer.lineno)))

    for item in ast.walk(node):
        if not isinstance(item, ast.Call):
            continue
        line = item.lineno
        callee = item.func
        call_name = ""
        owner = ""
        if isinstance(callee, ast.Name):
            call_name = callee.id
        elif isinstance(callee, ast.Attribute):
            call_name = callee.attr
            if isinstance(callee.value, ast.Name):
                owner = callee.value.id
        if not call_name:
            continue
        guarded = any(start <= line <= end for start, end in guards)
        if call_name in _SINK_NAMES or (
            call_name in _SINK_ATTRIBUTES and owner in {"os", "posix", "nt"}
        ):
            entries.add(
                _entry(f"dangerous_sink:{call_name}", name, line, guarded)
            )
        elif (owner, call_name) in _SINK_OWNED:
            entries.add(
                _entry(f"dangerous_sink:{owner}.{call_name}", name, line, guarded)
            )
        elif call_name == "Popen" and owner == "subprocess":
            if _keyword_true(item, "shell"):
                entries.add(
                    _entry("dangerous_sink:subprocess.shell_true", name, line, guarded)
                )
            else:
                entries.add(_entry("protection:subprocess_without_shell", name, line, guarded))
        elif call_name == "system" and not owner:
            entries.add(_entry(f"dangerous_sink:{call_name}", name, line, guarded))
        elif call_name in {"match", "search", "fullmatch"} and owner == "re":
            entries.add(_entry("input_validation:regex", name, line, guarded))
        elif call_name in _PROTECTION_CALLS:
            entries.add(
                _entry(f"{_PROTECTION_CALLS[call_name]}:{call_name}", name, line, guarded)
            )
    return entries


def _entry(kind: str, function: str, line: int, guarded: bool) -> str:
    suffix = ":guarded" if guarded else ""
    entry = f"{kind}@{function}:{line}{suffix}"
    return entry[:MAX_ENTRY_CHARS]


def _keyword_true(call: ast.Call, keyword: str) -> bool:
    for item in call.keywords:
        if item.arg == keyword:
            return isinstance(item.value, ast.Constant) and item.value.value is True
    return False
