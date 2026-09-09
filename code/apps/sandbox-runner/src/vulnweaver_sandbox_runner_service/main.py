"""Start the isolated Sandbox Runner with code-owned tool profiles."""

from __future__ import annotations

import os

import uvicorn
from vulnweaver_artifact_store import LocalContentAddressedStore
from vulnweaver_fuzzing import afl_casr_command_profile
from vulnweaver_sandbox_runner import DockerCliRuntime, SandboxRunner, create_sandbox_app
from vulnweaver_tool_runtime import ToolSpecLoader


def build_app():
    directory = os.environ.get("TOOL_SPEC_DIRECTORY", "/etc/vulnweaver/tool-specs")
    registry = ToolSpecLoader.load_directory(directory)
    digest = os.environ.get("AFL_CASR_IMAGE_DIGEST", "")
    if not digest:
        raise RuntimeError("AFL_CASR_IMAGE_DIGEST is required")
    profile = afl_casr_command_profile(
        os.environ.get("AFL_CASR_IMAGE_REF", "vulnweaver-afl-casr:fixed"),
        digest,
    )
    store = LocalContentAddressedStore(
        os.environ.get("ARTIFACT_STORE_ROOT", "/var/lib/vulnweaver/artifacts")
    )
    sandbox_root = os.environ.get("SANDBOX_ROOT", "/var/lib/vulnweaver/sandbox")
    runner = SandboxRunner(
        store,
        registry,
        [profile],
        runtime=DockerCliRuntime(root=sandbox_root),
        root=sandbox_root,
    )
    return create_sandbox_app(runner, bearer_token=os.environ.get("SANDBOX_RUNNER_TOKEN"))


app = build_app()


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
