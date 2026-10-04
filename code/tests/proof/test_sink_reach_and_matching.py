"""RA-01/RA-03 entrypoint-level regressions.

RA-01: the target-worker's C-call sink profiling surfaces in the observation
as per-run ``sink_fired`` (exit 20), is never a crash, and leaves the verdict
logic untouched. RA-03: constraint extraction from the audit report must pin
the exact finding — a missing address on either side never compares equal.
"""

from __future__ import annotations

import asyncio
import io
import json
from pathlib import Path
from typing import Any, cast

from vulnweaver_artifact_store import LocalContentAddressedStore
from vulnweaver_contracts import ArtifactKind, Finding, FindingCategory, FindingStatus, Severity
from vulnweaver_proof import (
    ProofExecutionService,
    build_execution_bundle,
    load_execution_bundle_member,
)
from vulnweaver_proof.verifier import SINK_FIRED_EXIT_CODE

from tests.proof.test_auto_poc import TIMESTAMP
from tests.proof.test_entrypoint import _execute


def test_sink_firing_target_completes_with_sink_flag(tmp_path: Any) -> None:
    """A target that evals marks the run sink_fired and stays non-crashed."""

    target = "def parse(value):\n    return eval(value)\n"
    driver = json.dumps({"target_callable": "parse", "input_mode": "text"})
    code, report = _execute(
        tmp_path,
        driver,
        target_source=target,
        crafted_input="1+1",
        control_input="2+2",
    )

    assert code == 0
    # eval("1+1") vs eval("2+2") return different values: an honest behavior
    # difference verdict, with every run flagged for the sink fire.
    assert report["verdict"] == "verified_behavior"
    assert report["verdict_reasons"] == [
        "behavior_difference_observed", "control_input_clean", "replay_stable",
    ]
    assert report["observed_behavior"] is not None
    assert report["observed_behavior"]["differed"] is True
    assert all(run["sink_fired"] is True for run in report["runs"])
    assert all(run["exit_code"] == SINK_FIRED_EXIT_CODE for run in report["runs"])
    # The sink fire must not read as a crash or a target exception.
    assert all(run["target_frames"] is False for run in report["runs"])


def test_clean_target_reports_no_sink_fire(tmp_path: Any) -> None:
    target = "def parse(value):\n    return len(value)\n"
    driver = json.dumps({"target_callable": "parse", "input_mode": "text"})
    code, report = _execute(
        tmp_path,
        driver,
        target_source=target,
        crafted_input="aaaa",
        control_input="bbbb",
    )

    assert code == 0
    assert report["verdict_reasons"] == ["no_behavior_difference"]
    assert all(run["sink_fired"] is False for run in report["runs"])
    assert all(run["exit_code"] == 0 for run in report["runs"])


# -- RA-03: constraint extraction pins the exact finding -----------------------


def _executor_with_store(tmp_path: Any) -> tuple[Any, LocalContentAddressedStore]:
    """ProofJobExecutor exposes the constraint extractor; no DB is needed."""

    from vulnweaver_proof import ProofJobExecutor

    store = LocalContentAddressedStore(cast(Any, tmp_path))
    executor = ProofJobExecutor(
        cast(Any, None),
        ProofExecutionService(
            cast(Any, _NullSandbox()),
            tool_name="proof-tool",
            tool_version="1.0.0",
            store=store,
        ),
        store=store,
    )
    return executor, store


class _NullSandbox:
    async def run(self, request: object, cancellation: object) -> dict[str, object]:
        raise AssertionError("sandbox must not run during constraint extraction")


def _finding_without_address(identifier: str, path: str, line: int) -> Finding:
    return cast(
        Finding,
        {
            "schema_version": "1.0.0",
            "id": identifier,
            "task_id": "task:constraint",
            "category": FindingCategory.AUTH_OR_BUSINESS_LOGIC,
            "cwe_id": "CWE-613",
            "title": "session never expires",
            "severity": Severity.HIGH,
            "confidence": 0.5,
            "location": {
                "artifact_version_id": "artifact-version:constraint",
                "path": path,
                "start_line": line,
                "start_column": 1,
                "end_line": line,
                "end_column": 2,
            },
            "dataflow": [],
            "call_path": [],
            "status": FindingStatus.CANDIDATE,
            "evidence_ids": [],
            "review_ids": [],
            "poc_ids": [],
            "fix_suggestion": "enforce expiry",
            "created_at": TIMESTAMP,
        },
    )


def _store_report(store: LocalContentAddressedStore, entries: list[dict[str, object]]) -> str:
    report = {"schema_version": "1.0.0", "report": {"findings": entries}}
    stored = store.put_stream(
        io.BytesIO(json.dumps(report).encode("utf-8")), max_bytes=1024 * 1024
    )
    return stored.object_ref


def test_constraint_extraction_requires_exact_location(tmp_path: Any) -> None:
    """RA-03: same-CWE entries without addresses never match by absence."""

    executor, store = _executor_with_store(tmp_path)
    report_ref = _store_report(
        store,
        [
            {
                "cwe_id": "CWE-613",
                "title": "first rule",
                "constraint": "first rule constraint",
            },
            {
                "cwe_id": "CWE-613",
                "title": "second rule",
                "path": "auth.py",
                "start_line": 5,
                "constraint": "second rule constraint",
            },
        ],
    )
    finding = _finding_without_address("finding:a", "auth.py", 5)
    extracted = asyncio.run(executor._constraint_from_report(report_ref, finding))
    # The address-less first entry must not match; the exact path/line wins.
    assert extracted == "second rule constraint"


def test_constraint_extraction_ignores_partial_location_matches(tmp_path: Any) -> None:
    """Same path but a different line, or line-only entries, never match."""

    executor, store = _executor_with_store(tmp_path)
    report_ref = _store_report(
        store,
        [
            {
                "cwe_id": "CWE-613",
                "path": "auth.py",
                "start_line": 9,
                "constraint": "wrong line",
            },
            {
                "cwe_id": "CWE-613",
                "start_line": 5,
                "constraint": "line without path",
            },
        ],
    )
    finding = _finding_without_address("finding:a", "auth.py", 5)
    extracted = asyncio.run(executor._constraint_from_report(report_ref, finding))
    assert extracted is None


def test_constraint_extraction_matches_binary_address_on_both_sides(
    tmp_path: Any,
) -> None:
    executor, store = _executor_with_store(tmp_path)
    report_ref = _store_report(
        store,
        [
            {
                "cwe_id": "CWE-613",
                "address": 0x401000,
                "constraint": "address rule",
            }
        ],
    )
    finding = cast(
        Finding,
        {
            **_finding_without_address("finding:a", "auth.py", 5),
            "location": {
                "artifact_version_id": "artifact-version:constraint",
                "virtual_address": 0x401000,
                "image_base": 0x400000,
            },
        },
    )
    extracted = asyncio.run(executor._constraint_from_report(report_ref, finding))
    assert extracted == "address rule"


# -- bundle round trip with the sink-fired run shape ---------------------------


def test_bundle_member_round_trip_returns_target_bytes(tmp_path: Any) -> None:
    """The worker's protection scan reads the exact bound target bytes back."""

    store = LocalContentAddressedStore(cast(Any, tmp_path))
    target_text = b"def parse(value):\n    return eval(value)\n"
    target = store.put_stream(io.BytesIO(target_text), max_bytes=1024 * 1024)
    driver = store.put_stream(
        io.BytesIO(b'{"target_callable":"parse","input_mode":"text"}'), max_bytes=1024
    )
    crafted = store.put_stream(io.BytesIO(b"1+1"), max_bytes=1024)
    control = store.put_stream(io.BytesIO(b"2+2"), max_bytes=1024)
    bundle = build_execution_bundle(
        store,
        bundle_id="execution-bundle:roundtrip",
        finding_id="finding:roundtrip",
        driver_ref=driver.object_ref,
        target_binding={
            "artifact_id": "artifact:roundtrip",
            "version_id": "artifact-version:roundtrip",
            "artifact_kind": ArtifactKind.SOURCE_ARCHIVE,
            "digest": target.digest,
        },
        target_ref=target.object_ref,
        input_refs=[crafted.object_ref],
        control_refs=[control.object_ref],
        created_at=TIMESTAMP,
    )
    assert (
        load_execution_bundle_member(store, bundle.stored.object_ref, "target")
        == target_text
    )
    assert (
        load_execution_bundle_member(store, bundle.stored.object_ref, "driver.json")
        == b'{"target_callable":"parse","input_mode":"text"}'
    )
    assert load_execution_bundle_member(store, bundle.stored.object_ref, "missing") is None


def test_worker_sink_lexicon_covers_documented_sinks() -> None:
    """The worker's inline lexicon stays aligned with the documented one."""

    worker = (
        Path(__file__).resolve().parents[2] / "apps/proof-tool/vulnweaver-proof-target-worker"
    )
    text = worker.read_text(encoding="utf-8")
    assert "SINK_LEXICON" in text
    for name in ("eval", "exec", "compile", "__import__", "loads", "system", "popen"):
        assert f'"{name}"' in text
