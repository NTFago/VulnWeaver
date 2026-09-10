from __future__ import annotations

from pathlib import Path
from typing import cast

from vulnweaver_binary_analysis import (
    assess_control_flow_flattening,
    recover_readable_pseudocode,
    validate_model_readable_pseudocode,
)
from vulnweaver_contracts import BinaryBasicBlock, BinaryPseudocode, BinaryXref


def test_recovery_labels_flattened_dispatcher_without_rewriting_evidence() -> None:
    fixture = (
        Path(__file__).parents[1]
        / "fixtures"
        / "teaching-samples"
        / "ollvm-style-flattened.c"
    )
    assert "switch (state)" in fixture.read_text(encoding="utf-8")
    assessments = assess_control_flow_flattening(
        [
            cast(
                BinaryBasicBlock,
                {
                    "function_name": "flattened",
                    "start_address": 0x401000,
                    "end_address": 0x401004,
                    "successor_addresses": [1, 2, 3, 4, 5],
                },
            )
        ],
        [
            cast(
                BinaryXref,
                {
                    "source_address": 0x401000,
                    "target_address": 0x401004,
                    "type": "jump",
                    "source_function": "flattened",
                    "target_symbol": None,
                },
            )
        ],
        min_score=0.45,
    )
    original = "LAB_401000:\nswitch (state) {\n  case 0x31: goto LAB_401010;\n}"
    recovered = recover_readable_pseudocode(
        (
            {
                "function_name": "flattened",
                "address": 0x401000,
                "text": original,
                "tool_name": "ghidra",
            },
        ),
        assessments,
        max_chars=4096,
    )

    assert "switch (state)" in original
    assert recovered[0]["tool_name"] == "vulnweaver-readable"
    assert "suspected flattened control flow" in recovered[0]["text"]
    assert "block 0x401000" in recovered[0]["text"]
    assert "control transfer to block 0x401010" in recovered[0]["text"]


def test_model_view_rejects_unanchored_or_oversized_functions() -> None:
    raw: tuple[BinaryPseudocode, ...] = (
        BinaryPseudocode(
            function_name="main",
            address=0x401000,
            text="return 0;",
            tool_name="ghidra",
        ),
    )
    accepted = validate_model_readable_pseudocode(
        raw,
        [
            {"address": 0x401000, "text": "int main(void) { return 0; }"},
            {"address": 0xDEADBEEF, "text": "invented"},
            {"address": 0x401000, "text": "x" * 33},
        ],
        max_chars=32,
    )
    assert accepted == (
        {
            "function_name": "main",
            "address": 0x401000,
            "text": "int main(void) { return 0; }",
            "tool_name": "model-readable",
        },
    )
