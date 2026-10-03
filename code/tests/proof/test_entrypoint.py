"""The proof image must execute the script bytes it receives."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ENTRYPOINT = Path(__file__).resolve().parents[2] / "apps/proof-tool/vulnweaver-proof-entrypoint"


def test_entrypoint_executes_the_supplied_python_file(tmp_path: Path) -> None:
    script = tmp_path / "proof.py"
    script.write_text('raise RuntimeError("script actually ran")\n', encoding="utf-8")
    output = tmp_path / "output"
    run = subprocess.run(
        [
            sys.executable, str(ENTRYPOINT), "--script", str(script),
            "--finding-id", "finding:test", "--kind", "proof_of_concept",
            "--output-dir", str(output),
        ],
        capture_output=True, text=True, check=False, timeout=10,
    )
    result = json.loads((output / "result.json").read_text(encoding="utf-8"))
    assert run.returncode == 1
    assert result["status"] == "failed"
    assert "script actually ran" in result["error"]
