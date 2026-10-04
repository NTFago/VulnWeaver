"""CR-04: the deterministic protection enumerator behind injection facts.

The scan is an independent control-plane source for ``protection_analysis``:
it walks the digest-bound target's AST — never model output, never a target
self-report — and lists the protection-relevant constructs around the bound
callable. The result must be deterministic (same bytes in, same list out) and
must refuse to claim anything when the sink cannot be resolved.
"""

from __future__ import annotations

from vulnweaver_proof.protection_analysis import scan_target_protections

TARGET = b'''
import html
import json
import pickle

def render(value):
    return eval(value)

def render_guarded(value):
    try:
        if isinstance(value, str):
            return eval(value)
    except Exception:
        return None

def render_escaped(value):
    return html.escape(eval(value))

def load(value):
    return pickle.loads(value)

def safe_load(value):
    return json.loads(value)
'''


def test_scan_enumerates_sink_and_guards_deterministically() -> None:
    first = scan_target_protections(TARGET, "render_guarded")
    second = scan_target_protections(TARGET, "render_guarded")
    assert first is not None and second is not None
    assert first.entries == second.entries
    assert first.sink.startswith("render_guarded@")
    entries = first.marker()
    assert any(entry.startswith("dangerous_sink:eval@") for entry in entries)
    assert any(entry.startswith("input_validation:isinstance@") for entry in entries)
    assert any(":guarded" in entry for entry in entries)
    # Every entry in the enumeration is stable and bounded.
    assert all(len(entry) <= 128 for entry in entries)
    assert len(entries) <= 32


def test_scan_of_unguarded_sink_reports_no_guard() -> None:
    scan = scan_target_protections(TARGET, "render")
    assert scan is not None
    assert any(
        entry.startswith("dangerous_sink:eval@") and ":guarded" not in entry
        for entry in scan.marker()
    )


def test_scan_detects_sanitizer_and_owned_sink_shapes() -> None:
    escaped = scan_target_protections(TARGET, "render_escaped")
    assert escaped is not None
    assert any(entry.startswith("sanitizer:escape@") for entry in escaped.marker())

    loader = scan_target_protections(TARGET, "load")
    assert loader is not None
    assert any(
        entry.startswith("dangerous_sink:pickle.loads@") for entry in loader.marker()
    )

    safe = scan_target_protections(TARGET, "safe_load")
    assert safe is not None
    # json.loads must not be flagged as a pickle-shaped dangerous sink.
    assert not any(
        entry.startswith("dangerous_sink:") for entry in safe.marker()
    )


def test_scan_refuses_unresolvable_or_invalid_input() -> None:
    assert scan_target_protections(TARGET, "missing_function") is None
    assert scan_target_protections(b"def broken(:\n", "broken") is None
    assert scan_target_protections(TARGET, "os.system") is None  # not an identifier path
    assert scan_target_protections(b"x" * (512 * 1024 + 1), "render") is None


def test_scan_follows_module_local_callees() -> None:
    source = (
        b"def helper(value):\n"
        b"    return eval(value)\n"
        b"def parse(value):\n"
        b"    return helper(value)\n"
    )
    scan = scan_target_protections(source, "parse")
    assert scan is not None
    assert scan.functions_scanned == 2
    assert any(entry.startswith("dangerous_sink:eval@") for entry in scan.marker())
    # The closure's sink entry anchors the scan to the bound callable.
    assert scan.sink.startswith("parse@")
    assert scan.marker()[0] != "" and scan.source_digest.startswith("sha256:")


# -- RG-03: the scan resolves the full dotted path, never a short-name guess ---


def test_scan_resolves_same_named_methods_by_class_path() -> None:
    """Two same-named methods: the class path pins the scanned node."""

    source = (
        b"class HandlerA:\n"
        b"    def parse(self, value):\n"
        b"        return len(value)\n"
        b"class HandlerB:\n"
        b"    def parse(self, value):\n"
        b"        return eval(value)\n"
    )
    clean = scan_target_protections(source, "HandlerA.parse")
    assert clean is not None
    assert not any(entry.startswith("dangerous_sink:") for entry in clean.marker())
    assert any(entry.startswith("callable_resolved:HandlerA.parse@") for entry in clean.marker())

    dangerous = scan_target_protections(source, "HandlerB.parse")
    assert dangerous is not None
    assert any(
        entry.startswith("dangerous_sink:eval@parse:") for entry in dangerous.marker()
    )


def test_scan_refuses_ambiguous_module_level_names() -> None:
    """A name defined twice at module scope cannot be pinned statically."""

    conditional = (
        b"if True:\n"
        b"    def parse(value):\n"
        b"        return eval(value)\n"
        b"else:\n"
        b"    def parse(value):\n"
        b"        return len(value)\n"
    )
    assert scan_target_protections(conditional, "parse") is None

    duplicated = (
        b"def parse(value):\n"
        b"    return eval(value)\n"
        b"def parse(value):\n"
        b"    return len(value)\n"
    )
    assert scan_target_protections(duplicated, "parse") is None

    aliased = (
        b"def real_parse(value):\n"
        b"    return eval(value)\n"
        b"parse = real_parse\n"
    )
    assert scan_target_protections(aliased, "parse") is None


def test_scan_refuses_class_paths_that_runtime_cannot_resolve() -> None:
    """Method paths on missing classes or function-prefixed chains refuse."""

    source = b"class Handler:\n    def parse(self, value):\n        return eval(value)\n"
    assert scan_target_protections(source, "Missing.parse") is None
    assert scan_target_protections(source, "parse") is None  # short name inside a class

    nested = (
        b"def outer(value):\n"
        b"    def inner(v):\n"
        b"        return eval(v)\n"
        b"    return inner(value)\n"
    )
    # The runtime resolves only module globals and class attributes; a
    # function-prefixed path cannot resolve there either.
    assert scan_target_protections(nested, "outer.inner") is None


def test_scan_class_method_closure_stays_in_scope() -> None:
    """A method's closure follows module functions, not other classes' bodies."""

    source = (
        b"def helper(value):\n"
        b"    return eval(value)\n"
        b"class Handler:\n"
        b"    def parse(self, value):\n"
        b"        return helper(value)\n"
    )
    scan = scan_target_protections(source, "Handler.parse")
    assert scan is not None
    assert scan.functions_scanned == 2
    assert any(entry.startswith("dangerous_sink:eval@") for entry in scan.marker())
    assert scan.sink.startswith("Handler.parse@")
