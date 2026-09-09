"""Generate bounded SARIF 2.1.0 output from canonical Findings."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, cast

from vulnweaver_contracts import Finding


def build_sarif(findings: Sequence[Finding]) -> dict[str, Any]:
    """Return SARIF without embedding evidence or unbounded tool logs."""
    results = [_result(finding) for finding in findings]
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
            cast(Mapping[str, Any], driver).get("name")
            if isinstance(driver, Mapping)
            else None
        )
        if driver_name != "VulnWeaver":
            raise ValueError("SARIF run must contain a tool driver")
        if not isinstance(typed_run.get("results"), list):
            raise ValueError("SARIF run results must be an array")


def _result(finding: Finding) -> dict[str, Any]:
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
        },
    }


def _location_uri(finding: Finding) -> str:
    location = finding["location"]
    value = location.get("path")
    return value[:4096] if isinstance(value, str) and value else "unknown"


def _region(finding: Finding) -> dict[str, int]:
    location = finding["location"]
    line = location.get("line")
    return {"startLine": line if isinstance(line, int) and line > 0 else 1}


def _enum_value(value: object) -> str:
    member = getattr(value, "value", value)
    return member if isinstance(member, str) else str(member)
