import asyncio
import os
import shutil
from pathlib import Path
from typing import cast

import pytest
from vulnweaver_contracts import ResourceBudget
from vulnweaver_sandbox_runner import DockerCliRuntime, RuntimeRequest

IMAGE_DIGEST = "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"


def test_docker_cli_runtime_executes_fixed_digest_with_isolation(tmp_path: Path) -> None:
    if os.environ.get("VULNWEAVER_DOCKER_RUNTIME_TEST") != "1":
        pytest.skip("set VULNWEAVER_DOCKER_RUNTIME_TEST=1 for Docker runtime verification")
    if shutil.which("docker") is None:
        pytest.skip("Docker CLI is unavailable; run this test in the dedicated sandbox runner")

    root = tmp_path / "sandbox"
    input_dir = root / "input"
    output_dir = root / "output"
    input_dir.mkdir(parents=True)
    output_dir.mkdir()
    budget = cast(
        ResourceBudget,
        {
            "max_model_tokens": 0,
            "cpu_millis": 250,
            "memory_bytes": 16 * 1024 * 1024,
            "disk_bytes": 1024 * 1024,
            "max_tool_concurrency": 1,
            "max_dynamic_runs": 0,
            "timeout_seconds": 10,
        },
    )
    request = RuntimeRequest(
        container_name="vw-sbx-integration",
        label="vulnweaver.sandbox=true",
        image_ref="alpine:3.20",
        image_digest=IMAGE_DIGEST,
        argv=("sh", "-c", "id -u > /output/uid.txt; touch /readonly-check"),
        input_dir=input_dir,
        output_dir=output_dir,
        resource_budget=budget,
        timeout_seconds=5,
        max_output_bytes=4096,
    )

    runtime = DockerCliRuntime(root=root)
    execution = asyncio.run(runtime.run(request, asyncio.Event()))
    try:
        assert execution.status == "succeeded"
        assert (output_dir / "uid.txt").read_text(encoding="utf-8").strip() == "10001"
        assert not (output_dir / "readonly-check").exists()
    finally:
        assert asyncio.run(runtime.cleanup(request.container_name))
        assert asyncio.run(runtime.list_owned(request.label)) == ()
