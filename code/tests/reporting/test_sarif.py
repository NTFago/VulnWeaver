from __future__ import annotations

from typing import cast

from vulnweaver_contracts import Finding
from vulnweaver_reporting import build_sarif, validate_sarif


def test_sarif_is_bounded_and_preserves_finding_identity() -> None:
    finding = cast(
        Finding,
        {
            "schema_version": "1.0.0",
            "id": "finding:1",
            "task_id": "task:1",
            "category": "command_injection",
            "cwe_id": "CWE-078",
            "title": "x" * 5000,
            "severity": "high",
            "confidence": 0.9,
            "location": {"path": "src/main.py", "line": 12},
            "dataflow": [],
            "call_path": [],
            "status": "candidate",
            "evidence_ids": [],
            "review_ids": [],
            "poc_ids": [],
            "fix_suggestion": "fix",
            "created_at": "2026-01-01T00:00:00+00:00",
        },
    )
    report = build_sarif([finding])
    result = report["runs"][0]["results"][0]
    assert report["version"] == "2.1.0"
    assert result["ruleId"] == "CWE-078"
    assert result["properties"]["findingId"] == "finding:1"
    assert len(result["message"]["text"]) == 4096
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 12
    validate_sarif(report)


def test_sarif_validation_rejects_incomplete_envelope() -> None:
    try:
        validate_sarif({"version": "2.1.0", "runs": [{}]})
    except ValueError as error:
        assert "SARIF" in str(error)
    else:
        raise AssertionError("invalid SARIF envelope was accepted")


def test_sarif_validation_rejects_wrong_schema_uri() -> None:
    report = build_sarif([])
    report["$schema"] = "https://example.invalid/sarif.json"
    try:
        validate_sarif(report)
    except ValueError:
        pass
    else:
        raise AssertionError("SARIF with wrong schema URI was accepted")


def test_sarif_validation_rejects_malformed_result() -> None:
    report = build_sarif([])
    report["runs"][0]["results"] = [{"ruleId": "CWE-1"}]
    try:
        validate_sarif(report)
    except ValueError as error:
        assert "level" in str(error)
    else:
        raise AssertionError("malformed SARIF result was accepted")


def test_sarif_expresses_the_call_path_as_a_thread_flow() -> None:
    finding = cast(
        Finding,
        {
            "schema_version": "1.0.0",
            "id": "finding:flow",
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
            "fix_suggestion": "fix",
            "created_at": "2026-01-01T00:00:00+00:00",
        },
    )

    result = build_sarif([finding])["runs"][0]["results"][0]

    locations = result["codeFlows"][0]["threadFlows"][0]["locations"]
    assert [
        item["location"]["physicalLocation"]["artifactLocation"]["uri"] for item in locations
    ] == ["src/app.c", "binary://0x401000"]
    assert locations[0]["location"]["physicalLocation"]["region"]["startLine"] == 10
    validate_sarif(build_sarif([finding]))


def test_sarif_omits_code_flows_without_a_call_path() -> None:
    finding = cast(
        Finding,
        {
            "schema_version": "1.0.0",
            "id": "finding:plain",
            "task_id": "task:1",
            "category": "injection",
            "cwe_id": "CWE-078",
            "title": "Injection",
            "severity": "high",
            "confidence": 0.9,
            "location": {"path": "src/main.py", "line": 12},
            "dataflow": [],
            "call_path": [],
            "status": "candidate",
            "evidence_ids": [],
            "review_ids": [],
            "poc_ids": [],
            "fix_suggestion": "fix",
            "created_at": "2026-01-01T00:00:00+00:00",
        },
    )

    assert build_sarif([finding])["runs"][0]["results"][0]["codeFlows"] == []
