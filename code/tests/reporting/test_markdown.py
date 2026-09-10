from __future__ import annotations

from typing import cast

from vulnweaver_contracts import Finding
from vulnweaver_reporting import build_markdown


def test_markdown_report_is_clear_for_no_findings() -> None:
    assert "No findings" in build_markdown([])


def test_markdown_renders_canonical_binary_location() -> None:
    finding = cast(
        Finding,
        {
            "schema_version": "1.0.0",
            "id": "finding:binary",
            "task_id": "task:1",
            "category": "static_only",
            "cwe_id": "CWE-22",
            "title": "Path issue",
            "severity": "medium",
            "confidence": 0.4,
            "location": {
                "artifact_version_id": "artifact-version:1",
                "virtual_address": 0x401000,
                "file_offset": 0,
            },
            "dataflow": [],
            "call_path": [],
            "status": "candidate",
            "evidence_ids": [],
            "review_ids": [],
            "poc_ids": [],
            "fix_suggestion": "Fix it",
            "created_at": "2026-01-01T00:00:00+00:00",
        },
    )

    assert "0x401000" in build_markdown([finding])


def test_markdown_report_references_evidence_without_embedding_logs() -> None:
    finding = cast(
        Finding,
        {
            "schema_version": "1.0.0",
            "id": "finding:1",
            "task_id": "task:1",
            "category": "injection",
            "cwe_id": "CWE-078",
            "title": "Injection",
            "severity": "high",
            "confidence": 0.9,
            "location": {
                "artifact_version_id": "artifact-version:1",
                "path": "main.py",
                "start_line": 3,
                "start_column": 1,
                "end_line": 4,
                "end_column": 4,
            },
            "dataflow": [],
            "call_path": [],
            "status": "confirmed",
            "evidence_ids": ["evidence:1"],
            "review_ids": ["review:1"],
            "poc_ids": [],
            "fix_suggestion": "Fix it",
            "created_at": "2026-01-01T00:00:00+00:00",
        },
    )
    report = build_markdown([finding])
    assert "finding:1" in report
    assert "main.py:3-4" in report
    assert "evidence:1" in report
    assert "Raw tool output" in report
    assert "1 referenced artifact" in report


def test_markdown_renders_evidence_artifact_and_crash_summary() -> None:
    finding = cast(
        Finding,
        {
            "schema_version": "1.0.0",
            "id": "finding:1",
            "task_id": "task:1",
            "category": "injection",
            "cwe_id": "CWE-078",
            "title": "Injection",
            "severity": "high",
            "confidence": 0.9,
            "location": {"path": "main.py", "line": 3},
            "dataflow": [],
            "call_path": [],
            "status": "confirmed",
            "evidence_ids": [],
            "review_ids": [],
            "poc_ids": [],
            "fix_suggestion": "Fix it",
            "created_at": "2026-01-01T00:00:00+00:00",
        },
    )
    evidence = {
        "finding:1": [
            cast(
                object,
                {
                    "schema_version": "1.0.0",
                    "id": "evidence:crash",
                    "type": "crash_record",
                    "strength": "strong",
                    "artifact_ref": "cas://minimized-input",
                    "digest": "sha256:" + "a" * 64,
                    "tool": None,
                    "input_ref": "cas://input",
                    "command_hash": None,
                    "exit_code": 11,
                    "stdout_ref": None,
                    "stderr_ref": None,
                    "replay_recipe": {"stack_hash": "sha256:" + "b" * 64},
                    "created_at": "2026-01-01T00:00:00Z",
                },
            )
        ]
    }
    report = build_markdown([finding], evidence=evidence)  # type: ignore[arg-type]
    assert "cas://minimized-input" in report
    assert "Crash stack" in report


def test_markdown_renders_the_projected_call_path() -> None:
    finding = cast(
        Finding,
        {
            "schema_version": "1.0.0",
            "id": "finding:call-path",
            "task_id": "task:1",
            "category": "memory_corruption",
            "cwe_id": "CWE-120",
            "title": "Overflow",
            "severity": "critical",
            "confidence": 0.8,
            "location": {"path": "src/app.c", "line": 10},
            "dataflow": [],
            "call_path": [
                {
                    "relation": "target",
                    "function_name": "handler",
                    "path": "src/app.c",
                    "line": 10,
                    "address": None,
                },
                {
                    "relation": "caller",
                    "function_name": "main",
                    "path": "src/main.c",
                    "line": 3,
                    "address": None,
                },
                {
                    "relation": "callee",
                    "function_name": "win_copy",
                    "path": None,
                    "line": None,
                    "address": 0x401000,
                },
            ],
            "status": "confirmed",
            "evidence_ids": [],
            "review_ids": [],
            "poc_ids": [],
            "fix_suggestion": "Fix it",
            "created_at": "2026-01-01T00:00:00+00:00",
        },
    )

    report = build_markdown([finding])

    assert "### Call path" in report
    assert "`target` handler (`src/app.c:10`)" in report
    assert "`caller` main (`src/main.c:3`)" in report
    assert "`callee` win_copy (`0x401000`)" in report


def test_markdown_omits_the_call_path_section_when_empty() -> None:
    finding = cast(
        Finding,
        {
            "schema_version": "1.0.0",
            "id": "finding:no-path",
            "task_id": "task:1",
            "category": "injection",
            "cwe_id": "CWE-078",
            "title": "Injection",
            "severity": "high",
            "confidence": 0.9,
            "location": {"path": "main.py", "line": 3},
            "dataflow": [],
            "call_path": [],
            "status": "confirmed",
            "evidence_ids": [],
            "review_ids": [],
            "poc_ids": [],
            "fix_suggestion": "Fix it",
            "created_at": "2026-01-01T00:00:00+00:00",
        },
    )

    assert "### Call path" not in build_markdown([finding])
