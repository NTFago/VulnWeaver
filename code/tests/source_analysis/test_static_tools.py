from __future__ import annotations

from vulnweaver_contracts import Severity, StaticToolStatus
from vulnweaver_source_analysis import (
    CppcheckAdapter,
    SemgrepAdapter,
    StaticToolOutput,
    parse_cppcheck_output,
    parse_semgrep_output,
)


def test_semgrep_json_is_normalized_to_contract_diagnostics() -> None:
    raw = (
        b'{"results":[{"check_id":"etc.vulnweaver.tool-specs.vulnweaver.python.eval",'
        b'"path":"src/app.py","start":{"line":4,"col":5},'
        b'"end":{"line":4,"col":18},"extra":{"message":"Avoid eval",'
        b'"severity":"ERROR","metadata":{"cwe":["CWE-95"]},'
        b'"metavars":{"$X":{"abstract_content":"value"}}}}]}'
    )

    diagnostics = parse_semgrep_output(raw, artifact_version_id="artifact-version:source")

    assert len(diagnostics) == 1
    diagnostic = diagnostics[0]
    assert diagnostic["tool_name"] == "semgrep"
    assert diagnostic["severity"] is Severity.HIGH
    assert diagnostic["location"]["path"] == "src/app.py"
    assert diagnostic["cwe_ids"] == ["CWE-95"]


def test_cppcheck_xml_is_normalized_and_invalid_xml_is_ignored() -> None:
    raw = (
        b'<results><errors><error id="bufferAccessOutOfBounds" severity="error" '
        b'msg="buffer access" cwe="119">'
        b'<location file="src/main.c" line="9" column="3"/>'
        b"</error></errors></results>"
    )

    diagnostics = parse_cppcheck_output(raw, artifact_version_id="artifact-version:source")

    assert len(diagnostics) == 1
    assert diagnostics[0]["tool_name"] == "cppcheck"
    assert diagnostics[0]["severity"] is Severity.HIGH
    assert diagnostics[0]["cwe_ids"] == ["CWE-119"]
    assert parse_cppcheck_output(b"not xml", artifact_version_id="artifact-version:source") == []

    output = StaticToolOutput(
        tool_name="cppcheck",
        tool_version="2.17.1",
        status=StaticToolStatus.SUCCEEDED,
        exit_code=0,
        stdout=b"",
        stderr=raw,
    )
    assert len(CppcheckAdapter().parse(output, artifact_version_id="artifact-version:source")) == 1


def test_missing_executable_becomes_structured_unavailable_result(tmp_path) -> None:
    config = tmp_path / "rules.yml"
    config.write_text("rules: []", encoding="utf-8")
    output = SemgrepAdapter(
        executable="vulnweaver-executable-does-not-exist",
        config_path=str(config),
    ).run(tmp_path, timeout_seconds=1)

    assert output.status is StaticToolStatus.UNAVAILABLE
    assert output.reason == "executable_not_found"
    assert output.exit_code is None
