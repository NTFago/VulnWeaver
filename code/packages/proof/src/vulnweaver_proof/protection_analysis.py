"""Deterministic protection enumeration over the digest-bound target (CR-04).

The injection ``FindingPolicy`` requires a ``protection_analysis`` fact. This
module is a control-plane AST enumerator that walks the bound callable and its
module-local callees in the exact source bytes the sandbox executed and lists
the protection-relevant constructs it sees — dangerous sinks, input
validation, exception guards, sanitizers and safe alternatives.

Role boundary (RA-01): this enumeration is a *diagnostic*. It lists calls that
exist in the source, not calls that executed, and it can therefore never prove
that input reached a sink. The reach fact comes solely from the interpreter-
level sink-fire observation (target-worker C-call profiling, exit 20); the
worker attaches this listing to injection evidence only alongside that
machine-verified reach, and the review gate maps it to ``protection_analysis``
only in that combination.

The result is deterministic for identical bytes, and a scan that cannot
resolve the bound callable claims nothing.
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

    The dotted callable path is resolved through the module AST exactly the way
    the target-worker resolves it at runtime (module global, then class
    attributes), so the scanned node is the executed function (RG-03). Any
    ambiguity — a name defined more than once at the same level, which static
    analysis cannot disambiguate against the runtime — refuses the scan
    instead of guessing. Returns ``None`` when the scan cannot run honestly:
    unparseable source, an unresolvable or ambiguous callable, or an oversized
    input. A successful scan always yields at least one entry (the resolved
    callable anchor).
    """

    if len(source) > MAX_SCAN_BYTES:
        return None
    parts = target_callable.split(".")
    if not parts or any(not part.isidentifier() or part.startswith("__") for part in parts):
        return None
    try:
        tree = ast.parse(source.decode("utf-8"))
    except (SyntaxError, ValueError, UnicodeDecodeError):
        return None

    sink = _resolve_ast_callable(tree, parts)
    if sink is None:
        return None
    sink_name = parts[-1]

    # Module-local callee closure starting at the sink: the code the crafted
    # input can reach without leaving the bound file. Only module-level
    # functions are followed — the runtime resolves calls in the module
    # namespace, so class-body helpers are not in the closure's name space.
    module_functions = _unique_top_level_functions(tree)
    selected: dict[str, ast.AST] = {sink_name: sink}
    frontier = [sink_name]
    depth = 0
    while frontier and depth < MAX_CLOSURE_DEPTH and len(selected) < MAX_CLOSURE_FUNCTIONS:
        next_frontier: list[str] = []
        for name in frontier:
            node = selected.get(name)
            if node is None:
                continue
            for callee in _local_callees(node, module_functions):
                if callee not in selected and len(selected) < MAX_CLOSURE_FUNCTIONS:
                    selected[callee] = module_functions[callee]
                    next_frontier.append(callee)
        frontier = next_frontier
        depth += 1

    entries: set[str] = set()
    for name, node in sorted(selected.items()):
        entries.update(_scan_function(name, node))
    # The bound callable itself resolved in the AST: always record the anchor,
    # so a scan over a clean function still documents what was enumerated.
    entries.add(_entry(f"callable_resolved:{target_callable}", sink_name, sink.lineno, False))
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


def _unique_top_level_functions(tree: ast.Module) -> dict[str, ast.AST]:
    """Module-level function defs, refusing any ambiguous (redefined) name.

    A name bound by more than one statement that executes at module scope —
    two defs, a def inside an ``if``/``try`` branch, or a def plus an
    assignment — has an implementation static analysis cannot pin against the
    runtime namespace, so the name is dropped entirely rather than guessed.
    """

    found: dict[str, ast.AST] = {}
    ambiguous: set[str] = set()
    for stmt in _module_scope_statements(tree):
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if stmt.name in found:
                ambiguous.add(stmt.name)
            else:
                found[stmt.name] = stmt
        elif isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    ambiguous.add(target.id)
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            ambiguous.add(stmt.target.id)
    return {name: node for name, node in found.items() if name not in ambiguous}


def _module_scope_statements(tree: ast.Module) -> list[ast.stmt]:
    """Statements that execute directly at module scope, through control flow.

    Conditional and exception branches may or may not execute their bodies;
    because the static view cannot know which branch ran, every def inside one
    is a candidate and the caller treats multiplied candidates as ambiguous.
    """

    statements: list[ast.stmt] = []
    stack: list[ast.stmt] = list(tree.body)
    while stack:
        stmt = stack.pop(0)
        statements.append(stmt)
        if isinstance(stmt, (ast.If, ast.For, ast.AsyncFor, ast.While)):
            stack.extend(stmt.body)
            stack.extend(stmt.orelse)
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            stack.extend(stmt.body)
        elif isinstance(stmt, ast.Try):
            stack.extend(stmt.body)
            stack.extend(stmt.orelse)
            stack.extend(stmt.finalbody)
            for handler in stmt.handlers:
                stack.extend(handler.body)
    return statements


def _resolve_ast_callable(
    tree: ast.Module, parts: list[str]
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Resolve a dotted callable path the way the runtime namespace would.

    Mirrors the target-worker's ``_resolve_target_callable``: the first segment
    is a module global, each middle segment must be a class, and the last is a
    function defined in that scope. Any ambiguity or mismatch refuses the scan
    (returns ``None``) instead of guessing which same-named node executes.
    """

    if len(parts) == 1:
        found = _unique_top_level_functions(tree).get(parts[0])
        return cast(ast.FunctionDef | ast.AsyncFunctionDef | None, found)
    current: ast.AST | None = _unique_top_level_classes(tree).get(parts[0])
    if current is None:
        return None
    for part in parts[1:-1]:
        if not isinstance(current, ast.ClassDef):
            return None
        nested = _unique_class_functions(current)
        current = nested.get(part)
        if current is None:
            return None
    final = parts[-1]
    if isinstance(current, ast.ClassDef):
        found = _unique_class_functions(current).get(final)
        return cast(ast.FunctionDef | ast.AsyncFunctionDef | None, found)
    return None


def _unique_top_level_classes(tree: ast.Module) -> dict[str, ast.ClassDef]:
    found: dict[str, ast.ClassDef] = {}
    ambiguous: set[str] = set()
    for stmt in _module_scope_statements(tree):
        if isinstance(stmt, ast.ClassDef):
            if stmt.name in found:
                ambiguous.add(stmt.name)
            else:
                found[stmt.name] = stmt
        elif isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    ambiguous.add(target.id)
    return {name: node for name, node in found.items() if name not in ambiguous}


def _unique_class_functions(class_node: ast.ClassDef) -> dict[str, ast.AST]:
    """Class-body function defs, refusing ambiguous or dynamically bound names."""

    found: dict[str, ast.AST] = {}
    ambiguous: set[str] = set()
    for stmt in class_node.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if stmt.name in found:
                ambiguous.add(stmt.name)
            else:
                found[stmt.name] = stmt
        elif isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    ambiguous.add(target.id)
    return {name: node for name, node in found.items() if name not in ambiguous}


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
