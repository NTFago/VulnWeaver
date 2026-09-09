from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from vulnweaver_contracts import Severity, StaticToolStatus
from vulnweaver_source_analysis import (
    CppcheckAdapter,
    SemgrepAdapter,
    StaticToolOutput,
    parse_cppcheck_output,
    parse_semgrep_output,
)
from vulnweaver_source_analysis.static_tools import (
    StaticToolOutputError,
    SubprocessStaticTool,
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


def test_cppcheck_xml_is_normalized_and_invalid_xml_is_rejected() -> None:
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
    with pytest.raises(StaticToolOutputError, match="cppcheck.invalid_xml_output"):
        parse_cppcheck_output(b"not xml", artifact_version_id="artifact-version:source")

    output = StaticToolOutput(
        tool_name="cppcheck",
        tool_version="2.17.1",
        status=StaticToolStatus.SUCCEEDED,
        exit_code=0,
        stdout=b"",
        stderr=raw,
    )
    assert len(CppcheckAdapter().parse(output, artifact_version_id="artifact-version:source")) == 1


@pytest.mark.skipif(os.name == "nt", reason="analysis-worker runs the Semgrep adapter on Linux")
def test_semgrep_uses_disposable_settings_outside_read_only_source_tree(tmp_path: Path) -> None:
    config = tmp_path / "rules.yml"
    config.write_text("rules: []", encoding="utf-8")
    executable = tmp_path / "semgrep-stub"
    executable.write_text(
        "#!/usr/bin/env python3\n"
        "import json\n"
        "import os\n"
        "from pathlib import Path\n"
        "settings = Path(os.environ['SEMGREP_SETTINGS_FILE'])\n"
        "assert Path(os.environ['HOME']) == settings.parent\n"
        "settings.write_text('metrics: off\\n', encoding='utf-8')\n"
        "print(json.dumps({'version': 'test', 'results': []}))\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    source = tmp_path / "source"
    source.mkdir()
    source.chmod(0o555)

    output = SemgrepAdapter(executable=str(executable), config_path=str(config)).run(
        source, timeout_seconds=5
    )

    assert output.status is StaticToolStatus.SUCCEEDED
    assert output.tool_version == "test"
    assert not (source / ".semgrep").exists()


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


@pytest.mark.parametrize("severity", ["information", "portability"])
def test_cppcheck_lowest_tier_severities_are_informational(severity: str) -> None:
    raw = (
        f'<results><errors><error id="notice" severity="{severity}" msg="notice">'
        '<location file="src/main.c" line="1"/></error></errors></results>'
    ).encode()

    diagnostics = parse_cppcheck_output(raw, artifact_version_id="artifact-version:source")

    assert diagnostics[0]["severity"] is Severity.INFO


def test_subprocess_output_is_killed_at_combined_limit(tmp_path) -> None:
    adapter = SubprocessStaticTool(
        "test",
        sys.executable,
        ("-c", "import sys; sys.stdout.buffer.write(b'x' * 1048576)"),
    )

    output = adapter.run(tmp_path, timeout_seconds=5, max_output_bytes=1024)

    assert output.status is StaticToolStatus.FAILED
    assert output.reason == "output_limit_exceeded"
    assert len(output.stdout) + len(output.stderr) <= 1024


def test_subprocess_does_not_inherit_control_plane_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql://secret")
    adapter = SubprocessStaticTool(
        "test",
        sys.executable,
        ("-c", "import os; print(os.getenv('DATABASE_URL', 'missing'))"),
    )

    output = adapter.run(tmp_path, timeout_seconds=5, max_output_bytes=1024)

    assert output.status is StaticToolStatus.SUCCEEDED
    assert output.stdout.strip() == b"missing"
