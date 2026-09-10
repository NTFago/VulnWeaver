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
