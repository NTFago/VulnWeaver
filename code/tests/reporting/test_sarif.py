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
        assert "tool driver" in str(error)
    else:
        raise AssertionError("invalid SARIF envelope was accepted")
