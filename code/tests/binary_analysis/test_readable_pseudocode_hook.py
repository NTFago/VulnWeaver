from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any, cast

from vulnweaver_analysis_worker.readable_pseudocode import ModelReadablePseudocodeHook
from vulnweaver_model_gateway import ModelTier


class _Gateway:
    def __init__(self) -> None:
        self.arguments: dict[str, object] | None = None

    async def complete_structured(self, **kwargs: object) -> object:
        self.arguments = kwargs
        return SimpleNamespace(
            failure=None,
            output={
                "schema_version": "1.0.0",
                "pseudocode": [
                    {
                        "function_name": "readable_main",
                        "address": 0x401000,
                        "text": "int readable_main(void) { return 0; }",
                    }
                ],
            },
        )


def test_model_hook_requests_bounded_audit_contract() -> None:
    async def scenario() -> None:
        gateway = _Gateway()
        hook = ModelReadablePseudocodeHook(cast(Any, gateway))
        rendered = await hook.render(
            cast(
                Any,
                {
                    "id": "job:1",
                    "task_id": "task:1",
                    "attempt": 1,
                    "input_refs": ["artifact-version:input"],
                    "resource_budget": {"max_model_tokens": 321},
                },
            ),
            (
                {
                    "function_name": "main",
                    "address": 0x401000,
                    "text": "return 0;",
                    "tool_name": "ghidra",
                },
            ),
            {"assessments": []},
        )

        assert rendered == [
            {
                "function_name": "readable_main",
                "address": 0x401000,
                "text": "int readable_main(void) { return 0; }",
            }
        ]
        assert gateway.arguments is not None
        assert gateway.arguments["tier"] is ModelTier.AUDIT
        assert gateway.arguments["output_contract"] == "ReadablePseudocodeReport"
        assert gateway.arguments["input_refs"] == ("artifact-version:input",)
        assert gateway.arguments["max_output_tokens"] == 321

    asyncio.run(scenario())
