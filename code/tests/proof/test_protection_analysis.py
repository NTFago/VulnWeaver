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
