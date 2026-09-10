"""Bounded structured LLM harness generation (source only)."""

from __future__ import annotations

from typing import Protocol

from vulnweaver_contracts import JsonObject
from vulnweaver_model_gateway import ModelCallResult, ModelTier


class HarnessModel(Protocol):
    async def complete_structured(
        self,
        *,
        tier: ModelTier,
        task_id: str,
        run_id: str,
        messages: list[dict[str, str]],
        output_contract: str,
        max_output_tokens: int | None = ...,
    ) -> ModelCallResult: ...


class HarnessGenerator:
    """Ask the planning model for source; never accepts commands or executes it."""

    def __init__(self, model: HarnessModel) -> None:
        self._model = model

    async def generate(self, *, task_id: str, job_id: str, context: JsonObject) -> str | None:
        response = await self._model.complete_structured(
            tier=ModelTier.PLANNING,
            task_id=task_id,
            run_id=f"agent-run:harness:{job_id}",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "Return HarnessSource JSON with source (1-65536 chars). "
                        "Emit source only; no shell, network, persistence or exploit code."
                    ),
                },
                {"role": "user", "content": str(context)},
            ],
            output_contract="HarnessSource",
            max_output_tokens=8192,
        )
        if response.failure is not None or response.output is None:
            return None
        source = response.output.get("source")
        if isinstance(source, str) and source.strip() and len(source) <= 65536:
            return source
        return None

    async def repair(
        self, *, task_id: str, job_id: str, source: str, diagnostics: str
    ) -> str | None:
        return await self.generate(
            task_id=task_id,
            job_id=f"{job_id}:repair",
            context={
                "previous_source": source,
                "compiler_diagnostics": diagnostics,
                "instruction": "Return corrected HarnessSource JSON only.",
            },
        )
