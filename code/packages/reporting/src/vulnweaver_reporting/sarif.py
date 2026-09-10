"""Generate bounded SARIF 2.1.0 output from canonical Findings."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, cast

from vulnweaver_contracts import Evidence, Finding, Poc


def build_sarif(
    findings: Sequence[Finding],
    pocs: Sequence[Poc] = (),
    evidence: dict[str, list[Evidence]] | None = None,
) -> dict[str, Any]:
    """Return SARIF without embedding evidence or unbounded tool logs."""
    poc_counts: dict[str, int] = {}
    poc_results: dict[str, list[str]] = {}
    for poc in pocs:
        poc_counts[poc["finding_id"]] = poc_counts.get(poc["finding_id"], 0) + 1
        if poc["result"] is not None:
            poc_results.setdefault(poc["finding_id"], []).append(_enum_value(poc["result"]))
    results = [
        _result(
            finding,
            poc_counts.get(finding["id"], 0),
            poc_results.get(finding["id"], []),
            (evidence or {}).get(finding["id"], []),
        )
        for finding in findings
    ]
    rules = {
        finding["cwe_id"]: {
            "id": finding["cwe_id"],
            "name": finding["title"][:256],
            "shortDescription": {"text": finding["title"][:1024]},
        }
        for finding in findings
    }
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "VulnWeaver",
                        "informationUri": "https://github.com/NTFago/VulnWeaver",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def validate_sarif(report: Mapping[str, Any]) -> None:
    """Validate the required SARIF envelope before publishing an artifact."""
    if (
        report.get("$schema") != "https://json.schemastore.org/sarif-2.1.0.json"
        or report.get("version") != "2.1.0"
        or not isinstance(report.get("runs"), list)
    ):
        raise ValueError("report is not a SARIF 2.1.0 document")
    for run in report["runs"]:
        if not isinstance(run, Mapping):
            raise ValueError("SARIF run must be an object")
        typed_run = cast(Mapping[str, Any], run)
        tool = typed_run.get("tool")
        if not isinstance(tool, Mapping):
            raise ValueError("SARIF run must contain a tool driver")
        typed_tool = cast(Mapping[str, Any], tool)
        driver = typed_tool.get("driver")
        driver_name = (
            cast(Mapping[str, Any], driver).get("name") if isinstance(driver, Mapping) else None
        )
        if driver_name != "VulnWeaver":
            raise ValueError("SARIF run must contain a tool driver")
        results = typed_run.get("results")
        if not isinstance(results, list):
            raise ValueError("SARIF run results must be an array")
        for result in cast(list[Any], results):
            if not isinstance(result, Mapping):
                raise ValueError("SARIF result must be an object")
            typed_result = cast(Mapping[str, Any], result)
            if not isinstance(typed_result.get("ruleId"), str):
                raise ValueError("SARIF result ruleId is required")
            if typed_result.get("level") not in {"error", "warning", "note", "none"}:
                raise ValueError("SARIF result level is invalid")
            message = typed_result.get("message")
            if not isinstance(message, Mapping) or not isinstance(
                cast(Mapping[str, Any], message).get("text"), str
            ):
                raise ValueError("SARIF result message.text is required")
            if not isinstance(typed_result.get("locations"), list):
                raise ValueError("SARIF result locations must be an array")


def _result(
    finding: Finding,
    poc_count: int = 0,
    poc_results: Sequence[str] = (),
    evidence: Sequence[Evidence] = (),
) -> dict[str, Any]:
    level = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }[_enum_value(finding["severity"])]
    return {
        "ruleId": finding["cwe_id"],
        "level": level,
        "message": {"text": finding["title"][:4096]},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": _location_uri(finding)},
                    "region": _region(finding),
                }
            }
        ],
        "properties": {
            "findingId": finding["id"],
            "status": _enum_value(finding["status"]),
            "confidence": finding["confidence"],
            "evidenceIds": list(finding["evidence_ids"]),
            "reviewIds": list(finding["review_ids"]),
            "pocCount": poc_count,
            "pocResults": list(poc_results),
            "evidence": [
                {
                    "id": item["id"],
                    "type": _enum_value(item["type"]),
                    "artifactRef": item["artifact_ref"][:4096],
                    "digest": item["digest"],
                    "replayKind": str(item["replay_recipe"].get("kind", "unknown"))[:128],
                }
                for item in evidence
            ],
        },
        "fixes": [{"description": {"text": finding["fix_suggestion"][:4096]}}],
    }


def _location_uri(finding: Finding) -> str:
    location = finding["location"]
    address = location.get("address")
    if isinstance(address, int):
        return f"binary://0x{address:x}"
    value = location.get("path")
    return value[:4096] if isinstance(value, str) and value else "unknown"


def _region(finding: Finding) -> dict[str, int]:
    location = finding["location"]
    line = location.get("line")
    return {"startLine": line if isinstance(line, int) and line > 0 else 1}


def _enum_value(value: object) -> str:
    member = getattr(value, "value", value)
    return member if isinstance(member, str) else str(member)
