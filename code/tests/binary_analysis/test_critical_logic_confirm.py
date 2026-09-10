from __future__ import annotations

import asyncio
from pathlib import Path
from typing import cast

from vulnweaver_binary_analysis import (
    BinaryAnalysisAggregate,
    BinaryAnalysisLimits,
    inspect_binary,
)
from vulnweaver_binary_analysis.executor import (
    _attach_critical_logic_candidates,
    _confirm_critical_logic,
)
from vulnweaver_contracts import (
    AgentRun,
    BinaryFunction,
    BinaryImport,
    BinaryString,
    Job,
    JsonObject,
    RunStatus,
    StructuredFailure,
)
from vulnweaver_model_gateway import ModelCallResult, ModelTier
from vulnweaver_orchestrator import CriticalLogicConfirmer

from tests.binary_analysis.samples import elf64_sample

TIMESTAMP = "2026-09-10T08:00:00Z"


def _aggregate(tmp_path: Path) -> BinaryAnalysisAggregate:
    binary_path = tmp_path / "key-logic.elf"
    binary_path.write_bytes(elf64_sample())
    return BinaryAnalysisAggregate(
        metadata=inspect_binary(binary_path),
        functions=[
            cast(
                BinaryFunction,
                {
                    "name": "authenticate_and_encrypt",
                    "address": 0x401000,
                    "size": 8,
                    "file_offset": 0x200,
                    "attributes": {},
                },
            )
        ],
        imports=[
            cast(
                BinaryImport,
                {
                    "library": "libcrypto.so",
                    "name": "EVP_EncryptInit",
                    "ordinal": None,
                    "address": 0x402000,
                },
            )
        ],
        strings=[
            cast(
                BinaryString,
                {
                    "value": "authenticate token",
                    "encoding": "ascii",
                    "file_offset": 0x300,
                    "virtual_address": 0x403000,
                },
            )
        ],
    )


def _job() -> Job:
    return cast(Job, {"id": "job:key-logic", "task_id": "task:key-logic"})


def _agent_run() -> AgentRun:
    return cast(
        AgentRun,
        {
            "schema_version": "1.0.0",
            "id": "agent-run:stub",
            "task_id": "task:key-logic",
            "status": RunStatus.SUCCEEDED,
            "model": "planning/test-model",
            "prompt_hash": "sha256:" + "a" * 64,
            "input_refs": [],
            "decisions": [],
            "token_usage": {"input_tokens": 4, "output_tokens": 4},
            "failure": None,
            "created_at": TIMESTAMP,
            "updated_at": TIMESTAMP,
        },
    )


def test_stamped_critical_logic_candidates_remain_unconfirmed(tmp_path: Path) -> None:
    aggregate = _aggregate(tmp_path)

    _attach_critical_logic_candidates(aggregate, BinaryAnalysisLimits())

    entries = aggregate.functions[0]["attributes"]["critical_logic"]
    assert {entry["category"] for entry in entries} == {"auth", "crypto"}
    assert all(entry["confirmed"] is None for entry in entries)
    assert all(entry["rationale"] is None for entry in entries)


def test_confirmation_merges_matching_category_verdicts(tmp_path: Path) -> None:
    class RecordingHook:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str, JsonObject]] = []

        async def confirm(
            self, *, task_id: str, job_id: str, candidates: JsonObject
        ) -> dict[str, list[JsonObject]]:
            self.calls.append((task_id, job_id, candidates))
            return {
                "authenticate_and_encrypt": [
                    {
                        "function_name": "authenticate_and_encrypt",
                        "category": "auth",
                        "confirmed": True,
                        "rationale": "authentication name and token evidence",
                    },
                    {
                        "function_name": "authenticate_and_encrypt",
                        "category": "crypto",
                        "confirmed": False,
                        "rationale": "import is insufficient to attribute crypto logic",
                    },
                ]
            }

    async def scenario() -> None:
        aggregate = _aggregate(tmp_path)
        _attach_critical_logic_candidates(aggregate, BinaryAnalysisLimits())
        hook = RecordingHook()

        await _confirm_critical_logic(_job(), aggregate, hook)

        assert [(task_id, job_id) for task_id, job_id, _ in hook.calls] == [
            ("task:key-logic", "job:key-logic")
        ]
        entries = {
            entry["category"]: entry
            for entry in aggregate.functions[0]["attributes"]["critical_logic"]
        }
        assert entries["auth"]["confirmed"] is True
        assert entries["crypto"]["confirmed"] is False
        assert entries["auth"]["rationale"] == "authentication name and token evidence"

    asyncio.run(scenario())


class _FakeCriticalLogicModel:
    def __init__(self, response: ModelCallResult) -> None:
        self._response = response
        self.calls: list[dict[str, object]] = []

    async def complete_structured(self, **kwargs: object) -> ModelCallResult:
        self.calls.append(kwargs)
        return self._response


def test_confirmer_maps_assessments_and_degrades_on_model_failure() -> None:
    async def scenario() -> None:
        success_model = _FakeCriticalLogicModel(
            ModelCallResult(
                cast(
                    JsonObject,
                    {
                        "schema_version": "1.0.0",
                        "assessments": [
                            {
                                "function_name": "authenticate_user",
                                "category": "auth",
                                "confirmed": True,
                                "rationale": "credential comparison controls access",
                            }
                        ],
                    },
                ),
                _agent_run(),
                None,
                "endpoint-1",
            )
        )
        verdicts = await CriticalLogicConfirmer(success_model).confirm(
            task_id="task:key-logic",
            job_id="job:key-logic",
            candidates={"authenticate_user": {"entries": []}},
        )
        assert success_model.calls[0]["tier"] is ModelTier.PLANNING
        assert verdicts == {
            "authenticate_user": [
                {
                    "function_name": "authenticate_user",
                    "category": "auth",
                    "confirmed": True,
                    "rationale": "credential comparison controls access",
                }
            ]
        }

        failure = StructuredFailure(
            code="model_unavailable",
            kind="dependency",
            message="planning model is unavailable",
            retryable=True,
            details={},
        )
        failed_model = _FakeCriticalLogicModel(
            ModelCallResult(None, _agent_run(), failure, None)
        )
        degraded = await CriticalLogicConfirmer(failed_model).confirm(
            task_id="task:key-logic",
            job_id="job:key-logic-failure",
            candidates={"authenticate_user": {"entries": []}},
        )
        assert degraded == {}

    asyncio.run(scenario())
