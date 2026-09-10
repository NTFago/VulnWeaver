import pytest
from vulnweaver_fuzzing.harness_generator import HarnessGenerator
from vulnweaver_model_gateway import ModelTier


class Model:
    def __init__(self, output=None, failure=None):
        self.output, self.failure, self.calls = output, failure, []

    async def complete_structured(self, **kwargs):
        self.calls.append(kwargs)
        return type("R", (), {"output": self.output, "failure": self.failure})()


@pytest.mark.anyio
async def test_generator_maps_source_and_planning_tier():
    model = Model({"source": "int LLVMFuzzerTestOneInput() { return 0; }"})
    source = await HarnessGenerator(model).generate(
        task_id="t", job_id="j", context={"finding": "f"}
    )
    assert source.startswith("int")
    assert model.calls[0]["tier"] is ModelTier.PLANNING
    assert model.calls[0]["output_contract"] == "HarnessSource"


@pytest.mark.anyio
async def test_generator_failure_or_invalid_output_returns_none():
    failed = HarnessGenerator(Model(failure={"code": "x"}))
    invalid = HarnessGenerator(Model({"source": "   "}))
    assert await failed.generate(task_id="t", job_id="j", context={}) is None
    assert await invalid.generate(task_id="t", job_id="j", context={}) is None
