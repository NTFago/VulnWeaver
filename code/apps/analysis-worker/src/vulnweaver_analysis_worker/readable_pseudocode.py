"""Model adapter for a bounded, review-only binary pseudocode view."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import cast

from vulnweaver_contracts import BinaryPseudocode, Job, JsonObject
from vulnweaver_model_gateway import ModelGateway, ModelTier

_MAX_MODEL_FUNCTIONS = 16
_MAX_INPUT_CHARS = 64 * 1024


class ModelReadablePseudocodeHook:
    """Ask the configured model for names, comments and structured control flow.

    The binary executor independently verifies that every returned item is
    anchored to an original function address before publishing it.
    """

    def __init__(self, gateway: ModelGateway) -> None:
        self._gateway = gateway

    async def render(
        self,
        job: Job,
        pseudocode: tuple[BinaryPseudocode, ...],
        obfuscation: JsonObject,
    ) -> Sequence[Mapping[str, object]]:
        selected = _bounded_pseudocode(pseudocode)
        response = await self._gateway.complete_structured(
            tier=ModelTier.AUDIT,
            task_id=job["task_id"],
            run_id=f"agent-run:readable-pseudocode:{job['id']}:{job['attempt']}",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You produce a review-only readable view of decompiled binary code. "
                        "Preserve behavior, do not invent functions or addresses, and do not "
                        "write exploit instructions. Keep uncertainty explicit in comments."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "task": "Improve control-flow structure, variable names, and comments "
                            "for these bounded pseudocode excerpts. Return only the required JSON.",
                            "pseudocode": selected,
                            "obfuscation": obfuscation,
                        },
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ),
                },
            ],
            output_contract="ReadablePseudocodeReport",
            input_refs=tuple(job["input_refs"]),
            max_output_tokens=min(8192, job["resource_budget"]["max_model_tokens"]),
        )
        if response.failure is not None or response.output is None:
            raise RuntimeError("readable_pseudocode.model_unavailable")
        values = response.output.get("pseudocode")
        return cast(Sequence[Mapping[str, object]], values if isinstance(values, list) else [])


def _bounded_pseudocode(pseudocode: Sequence[BinaryPseudocode]) -> list[dict[str, object]]:
    selected: list[dict[str, object]] = []
    remaining = _MAX_INPUT_CHARS
    for item in pseudocode[:_MAX_MODEL_FUNCTIONS]:
        if remaining <= 0:
            break
        text = item["text"][: min(8192, remaining)]
        selected.append(
            {
                "function_name": item["function_name"],
                "address": item["address"],
                "text": text,
            }
        )
        remaining -= len(text)
    return selected
