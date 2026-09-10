"""Start the isolated Sandbox Runner with code-owned tool profiles."""

from __future__ import annotations

import os
import subprocess

import uvicorn
from vulnweaver_artifact_store import LocalContentAddressedStore
from vulnweaver_binary_analysis import binary_command_profile, binary_tool_spec
from vulnweaver_contracts import ResourceBudget
from vulnweaver_fuzzing import afl_casr_command_profile, afl_casr_tool_spec
from vulnweaver_proof import proof_command_profile, proof_tool_spec
from vulnweaver_sandbox_runner import (
    DockerCliRuntime,
    SandboxCommandProfile,
    SandboxRunner,
    create_sandbox_app,
)
from vulnweaver_tool_runtime import ToolSpecLoader


def build_app():
    directory = os.environ.get("TOOL_SPEC_DIRECTORY", "/etc/vulnweaver/tool-specs")
    registry = ToolSpecLoader.load_directory(directory)
    digest = os.environ.get("AFL_CASR_IMAGE_DIGEST", "").strip()
    profiles: list[SandboxCommandProfile] = []
    proof_digest = os.environ.get("PROOF_IMAGE_DIGEST", "").strip()
    binary_ref = os.environ.get("BINARY_TOOLS_IMAGE_REF", "vulnweaver-binary-tools:fixed")
    binary_digest = os.environ.get("BINARY_TOOLS_IMAGE_DIGEST", "").strip()
    if not binary_digest:
        binary_digest = _resolve_local_image_digest(binary_ref)
    if binary_digest:
        registry.register(
            binary_tool_spec(
                binary_digest,
                _binary_resource_budget(),
            )
        )
        profiles.append(
                binary_command_profile(
                binary_ref,
                binary_digest,
            )
        )
    if proof_digest:
        registry.register(
            proof_tool_spec(
                proof_digest,
                _resource_budget(),
            )
        )
        profiles.append(
            proof_command_profile(
                os.environ.get("PROOF_IMAGE_REF", "vulnweaver-proof:fixed"),
                proof_digest,
            )
        )
    if digest:
        registry.register(
            afl_casr_tool_spec(
                digest,
                _fuzz_resource_budget(),
            )
        )
        profiles.append(
            afl_casr_command_profile(
                os.environ.get("AFL_CASR_IMAGE_REF", "vulnweaver-afl-casr:fixed"),
                digest,
            )
        )
    store = LocalContentAddressedStore(
        os.environ.get("ARTIFACT_STORE_ROOT", "/var/lib/vulnweaver/artifacts")
    )
    sandbox_root = os.environ.get("SANDBOX_ROOT", "/var/lib/vulnweaver/sandbox")
    runner = SandboxRunner(
        store,
        registry,
        profiles,
        runtime=DockerCliRuntime(
            root=sandbox_root,
            docker_host_root=os.environ.get("DOCKER_HOST_SANDBOX_ROOT") or None,
        ),
        root=sandbox_root,
    )
    token = os.environ.get("SANDBOX_RUNNER_TOKEN", "").strip() or None
    registered_digests: dict[tuple[str, str], str] = {}
    if binary_digest:
        registered_digests[("binary-facts", "1.0.0")] = binary_digest
    if proof_digest:
        registered_digests[("proof-tool", "1.0.0")] = proof_digest
    if digest:
        registered_digests[("afl-casr", "1.0.0")] = digest
    return create_sandbox_app(
        runner, bearer_token=token, tool_digests=registered_digests
    )


def _resource_budget() -> ResourceBudget:
    return {
        "max_model_tokens": 0,
        "cpu_millis": int(os.environ.get("PROOF_CPU_MILLIS", "1000")),
        "memory_bytes": int(os.environ.get("PROOF_MEMORY_BYTES", str(256 * 1024 * 1024))),
        "disk_bytes": int(os.environ.get("PROOF_DISK_BYTES", str(256 * 1024 * 1024))),
        "max_tool_concurrency": 1,
        "max_dynamic_runs": 1,
        "timeout_seconds": int(os.environ.get("PROOF_TIMEOUT_SECONDS", "120")),
    }


def _fuzz_resource_budget() -> ResourceBudget:
    return {
        "max_model_tokens": 0,
        "cpu_millis": int(os.environ.get("AFL_CPU_MILLIS", "4000")),
        "memory_bytes": int(os.environ.get("AFL_MEMORY_BYTES", str(1024 * 1024 * 1024))),
        "disk_bytes": int(os.environ.get("AFL_DISK_BYTES", str(512 * 1024 * 1024))),
        "max_tool_concurrency": 1,
        "max_dynamic_runs": 1,
        "timeout_seconds": int(os.environ.get("AFL_TIMEOUT_SECONDS", "300")),
    }


def _binary_resource_budget() -> ResourceBudget:
    return {
        "max_model_tokens": 0,
        "cpu_millis": int(os.environ.get("BINARY_CPU_MILLIS", "4000")),
        "memory_bytes": int(os.environ.get("BINARY_MEMORY_BYTES", str(3 * 1024 * 1024 * 1024))),
        "disk_bytes": int(os.environ.get("BINARY_DISK_BYTES", str(1024 * 1024 * 1024))),
        "max_tool_concurrency": 1,
        "max_dynamic_runs": 0,
        "timeout_seconds": int(os.environ.get("BINARY_TIMEOUT_SECONDS", "600")),
    }


def _resolve_local_image_digest(image_ref: str) -> str:
    """Resolve a locally built fixed image without weakening digest pinning."""
    try:
        result = subprocess.run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", image_ref],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    digest = result.stdout.strip()
    return digest if digest.startswith("sha256:") else ""


app = build_app()


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
