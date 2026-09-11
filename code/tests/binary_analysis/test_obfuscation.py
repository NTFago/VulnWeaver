from vulnweaver_binary_analysis import assess_control_flow_flattening


def _block(name: str, count: int, start: int) -> dict[str, object]:
    return {
        "function_name": name,
        "start_address": start,
        "end_address": start + 4,
        "successor_addresses": list(range(count)),
    }


def _xref(name: str, target: str | None) -> dict[str, object]:
    return {
        "source_address": 1,
        "target_address": 2,
        "type": "jump",
        "source_function": name,
        "target_symbol": target,
    }


def test_control_flow_flattening_reports_explainable_dispatcher_signal() -> None:
    result = assess_control_flow_flattening(
        [_block("dispatch", 5, 1), _block("dispatch", 1, 5)],
        [_xref("dispatch", None)],
        min_score=0.45,
    )
    assert len(result) == 1
    assert result[0].flattened is True
    assert result[0].dispatcher_blocks == 1
    assert "indirect jumps" in result[0].reason


def test_control_flow_flattening_does_not_flag_normal_cfg() -> None:
    result = assess_control_flow_flattening(
        [_block("main", 2, 1), _block("main", 1, 5)],
        [_xref("main", "callee")],
    )
    assert result[0].flattened is False
    assert result[0].indirect_jumps == 0


def _dispatcher_function(name: str, *, reentered: bool) -> list[dict[str, object]]:
    """One wide block plus case bodies, optionally looping back to the dispatch."""
    blocks: list[dict[str, object]] = [
        {
            "function_name": name,
            "start_address": 0x1000,
            "end_address": 0x1004,
            "successor_addresses": [0x1010, 0x1020, 0x1030, 0x1040, 0x1050],
        },
        {
            "function_name": name,
            "start_address": 0x1010,
            "end_address": 0x1014,
            "successor_addresses": [0x1000] if reentered else [0x1060],
        },
    ]
    for start in (0x1020, 0x1030, 0x1040, 0x1050):
        blocks.append(
            {
                "function_name": name,
                "start_address": start,
                "end_address": start + 4,
                "successor_addresses": [0x1060],
            }
        )
    blocks.append(
        {
            "function_name": name,
            "start_address": 0x1060,
            "end_address": 0x1064,
            "successor_addresses": [],
        }
    )
    return blocks


def test_control_flow_flattening_flags_a_reentered_dispatcher() -> None:
    """Flat-lifted code loops back through its dispatcher on every case."""
    result = assess_control_flow_flattening(
        _dispatcher_function("flat", reentered=True),
        [_xref("flat", None)],
    )
    assert result[0].dispatcher_blocks == 1
    assert result[0].flattened is True
    assert "re-entered" in result[0].reason


def test_control_flow_flattening_does_not_flag_an_ordinary_switch() -> None:
    """A `switch` also fans out, but its dispatcher is entered once and left.

    Fan-out alone would call every jump table obfuscated; requiring control to
    return to the dispatcher is what keeps ordinary dispatch out of the result.
    """
    result = assess_control_flow_flattening(
        _dispatcher_function("switchy", reentered=False),
        [_xref("switchy", None)],
    )
    assert result[0].dispatcher_blocks == 0
    assert result[0].flattened is False
