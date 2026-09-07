from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from jsonschema import Draft202012Validator
from vulnweaver_contracts import SCHEMA_VERSION, get_contract_schema

CODE_ROOT = Path(__file__).resolve().parents[2]
GENERATOR = CODE_ROOT / "packages" / "contracts" / "scripts" / "generate_contracts.py"


def test_schema_bundle_is_valid_draft_2020_12() -> None:
    schema_path = (
        CODE_ROOT
        / "packages"
        / "contracts"
        / "src"
        / "vulnweaver_contracts"
        / "schemas"
        / "v1"
        / "contracts.schema.json"
    )
    Draft202012Validator.check_schema(json.loads(schema_path.read_text(encoding="utf-8")))


def test_generated_contracts_are_current() -> None:
    result = subprocess.run(
        [sys.executable, str(GENERATOR), "--check"],
        cwd=CODE_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_frozen_schema_version_is_exposed() -> None:
    schema = get_contract_schema("SchemaVersion")
    assert SCHEMA_VERSION == "1.0.0"
    assert schema["$defs"]["SchemaVersion"]["enum"] == [SCHEMA_VERSION]
