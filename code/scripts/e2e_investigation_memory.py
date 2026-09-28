"""In-network E2E: investigation memory accumulates across two tasks.

Runs inside the compose control-plane network against the live api service.
Submits two tasks over the same XOR-packed sample in one project and asserts
the project ends up with an investigation-memory artifact holding one version
per completed audit -- the durable trace of the agent's own conclusions.
"""

from __future__ import annotations

import sys
import time

import httpx

BASE = "http://api:8000"
USERNAME = "vw-e2e"
PASSWORD = "VwE2e-2026-Unpack-Chain"


def main() -> int:
    client = httpx.Client(base_url=BASE, timeout=60.0)
    register = client.post(
        "/api/auth/register",
        json={"schema_version": "1.0.0", "username": USERNAME, "password": PASSWORD},
    )
    if register.status_code not in (200, 201):
        login = client.post(
            "/api/auth/login",
            json={"schema_version": "1.0.0", "username": USERNAME, "password": PASSWORD},
        )
        login.raise_for_status()
        payload = login.json()
    else:
        payload = register.json()
    write_headers = {"X-CSRF-Token": payload["csrf_token"]}

    from tests.binary_analysis.samples import elf64_sample, packed_elf64_sample

    inner = elf64_sample()
    outer = bytearray(packed_elf64_sample(keep_sections=False, alphabet=256))
    outer[0x1000 : 0x1000 + len(inner)] = bytes(value ^ 0x5A for value in inner)

    project = client.post(
        "/api/projects",
        headers={**write_headers, "Idempotency-Key": f"proj-mem-{int(time.time())}"},
        json={
            "schema_version": "1.0.0",
            "name": f"memory-e2e-{int(time.time())}",
            "input_scope": ["local-sample"],
            "permission_mode": "request_permission",
            "exploit_validation_enabled": False,
        },
    )
    project.raise_for_status()
    project_id = project.json()["id"]
    print("project:", project_id)

    upload = client.post(
        f"/api/projects/{project_id}/artifacts",
        params={"kind": "elf"},
        headers={
            **write_headers,
            "Idempotency-Key": f"upload-mem-{int(time.time())}",
            "X-Artifact-Filename": "xor-packed-sample.bin",
            "Content-Type": "application/octet-stream",
        },
        content=bytes(outer),
    )
    upload.raise_for_status()
    version_id = upload.json()["versions"][0]["id"]

    terminal = {"succeeded", "failed", "cancelled"}
    for attempt_index in range(2):
        task = client.post(
            f"/api/projects/{project_id}/tasks",
            headers={
                **write_headers,
                "Idempotency-Key": f"task-mem-{int(time.time())}-{attempt_index}",
            },
            json={"schema_version": "1.0.0", "artifact_version_ids": [version_id]},
        )
        task.raise_for_status()
        task_id = task.json()["id"]
        print(f"task {attempt_index + 1}:", task_id)
        for _poll in range(150):
            time.sleep(5)
            jobs = client.get(f"/api/tasks/{task_id}/jobs").json()
            summary = {job["kind"]: job["status"] for job in jobs}
            if jobs and all(job["status"] in terminal for job in jobs):
                print(f"  settled: {summary}")
                break
        else:
            print("TIMEOUT waiting for jobs")
            return 1
        audit = [job for job in jobs if job["kind"] == "semantic_audit"]
        if not audit or audit[0]["status"] != "succeeded":
            print("FAIL: semantic_audit did not succeed")
            return 1

    listing = client.get(f"/api/projects/{project_id}/artifacts").json()
    memory = None
    for listed in listing:
        detail = client.get(f"/api/projects/{project_id}/artifacts/{listed['id']}").json()
        for version in detail["versions"]:
            config = version.get("generation_config") or {}
            if config.get("format") == "investigation-memory":
                memory = detail
    if memory is None:
        print("FAIL: no investigation-memory artifact in the project")
        return 1
    versions = memory["versions"]
    print("investigation-memory versions:", len(versions))
    if len(versions) < 2:
        print("FAIL: expected one memory version per completed audit")
        return 1
    print("E2E OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
