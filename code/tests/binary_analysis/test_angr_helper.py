# pyright: reportPrivateUsage=false
from __future__ import annotations

import sys
from dataclasses import dataclass

import pytest
from vulnweaver_binary_analysis.angr_helper import _symbolically_explore, main


@dataclass
class _State:
    addr: int


class _Manager:
    def __init__(self, address: int) -> None:
        self.active = [_State(address), _State(address + 1)]
        self.unconstrained = [_State(address + 2)]
        self.stashes = {"active": self.active}

    def step(self) -> None:
        self.active = [_State(item.addr + 4) for item in self.stashes["active"]]
        self.stashes["active"] = self.active

    def drop(self, *, stash: str) -> None:
        if stash == "unconstrained":
            self.unconstrained = []


class _Factory:
    def blank_state(self, *, addr: int) -> _State:
        return _State(addr)

    def simulation_manager(self, state: _State) -> _Manager:
        return _Manager(state.addr)


class _Project:
    factory = _Factory()


class _FailingFactory:
    def blank_state(self, *, addr: int) -> _State:
        del addr
        raise RuntimeError("fixture failure")


class _FailingProject:
    factory = _FailingFactory()


def test_symbolic_helper_bounds_steps_and_active_states() -> None:
    result = _symbolically_explore(_Project(), 0x401000, step_limit=2, state_limit=1)

    assert result["function_address"] == 0x401000
    assert result["status"] == "partial"
    assert result["steps"] == 2
    assert result["explored_states"] == 2
    assert result["reached_addresses"] == [0x401000, 0x401004]
    assert result["unconstrained_states"] == 1
    assert result["reason"] == "state_or_step_limit"


def test_symbolic_helper_records_per_target_failures() -> None:
    result = _symbolically_explore(_FailingProject(), 0x401000, step_limit=2, state_limit=1)

    assert result == {
        "function_address": 0x401000,
        "status": "failed",
        "steps": 0,
        "explored_states": 0,
        "reached_addresses": [],
        "unconstrained_states": 0,
        "reason": "RuntimeError",
    }


def test_angr_helper_rejects_missing_target_argument(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "angr_helper",
            "input.bin",
            "output.json",
            "10",
            "20",
            "30",
            "40",
            "2",
            "3",
        ],
    )
    with pytest.raises(SystemExit, match="usage: angr_helper"):
        main()
