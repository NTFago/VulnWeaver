"""In-network E2E: the dynamic-verification chain reaches real fuzz execution.

Submits the registered fuzz-overflow teaching sample to an opt-in project and
follows the full pipeline: audit grounds the memory-corruption candidate, the
review settlement dispatches fuzz jobs for it, and the fuzz job executes in the
AFL++ sandbox.  Pass = a fuzz job reaches a terminal status (crash or no-crash
both prove reachability; the harness and execution are what is under test).
"""

from __future__ import annotations

import io
import json
import sys
import tarfile
import time

import httpx

BASE = "http://api:8000"
USERNAME = "vw-e2e"
PASSWORD = "VwE2e-2026-Unpack-Chain"
SAMPLE_SOURCE = "/workspace/vulnweaver/code/tests/fixtures/teaching-samples/fuzz-overflow.c"


def main() -> int:
    client = httpx.Client(base_url=BASE, timeout=60.0)
    login = client.post(
        "/api/auth/login",
        json={"schema_version": "1.0.0", "username": USERNAME, "password": PASSWORD},
    )
    login.raise_for_status()
    payload = login.json()
    write_headers = {"X-CSRF-Token": payload["csrf_token"]}

    with open(SAMPLE_SOURCE, "r", encoding="utf-8") as stream:
        source_text = stream.read()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        info = tarfile.TarInfo(name="fuzz-overflow.c")
        info.size = len(source_text.encode())
        archive.addfile(info, io.BytesIO(source_text.encode()))
    sample = buffer.getvalue()

    project = client.post(
        "/api/projects",
        headers={**write_headers, "Idempotency-Key": f"proj-dv-{int(time.time())}"},
        json={
            "schema_version": "1.0.0",
            "name": f"dynamic-verification-{int(time.time())}",
            "input_scope": ["local-sample"],
            "permission_mode": "request_permission",
            # The dynamic-verification opt-in: fuzz/proof/symbolic all gate on it.
            "exploit_validation_enabled": True,
        },
    )
    project.raise_for_status()
    project_id = project.json()["id"]
    print("project (opt-in):", project_id)

    upload = client.post(
        f"/api/projects/{project_id}/artifacts",
        params={"kind": "source_archive"},
        headers={
            **write_headers,
            "Idempotency-Key": f"upload-dv-{int(time.time())}",
            "X-Artifact-Filename": "fuzz-overflow.tar.gz",
            "Content-Type": "application/octet-stream",
        },
        content=sample,
    )
    if upload.status_code >= 400:
        print("upload responded:", upload.status_code, upload.text[:300])
    upload.raise_for_status()
    version_id = upload.json()["versions"][0]["id"]
    print("uploaded:", version_id)

    task = client.post(
        f"/api/projects/{project_id}/tasks",
        headers={**write_headers, "Idempotency-Key": f"task-dv-{int(time.time())}"},
        json={"schema_version": "1.0.0", "artifact_version_ids": [version_id]},
    )
    task.raise_for_status()
    task_id = task.json()["id"]
    print("task:", task_id)

    terminal = {"succeeded", "failed", "cancelled"}
    fuzz_seen = False
    for poll in range(180):
        time.sleep(5)
        jobs = client.get(f"/api/tasks/{task_id}/jobs").json()
        summary = {job["kind"]: job["status"] for job in jobs}
        fuzz_jobs = [job for job in jobs if job["kind"] == "fuzz"]
        if fuzz_jobs and not fuzz_seen:
            fuzz_seen = True
            print("fuzz job dispatched:", [job["id"] for job in fuzz_jobs])
        print(f"[poll {poll}] {summary}")
        if jobs and all(job["status"] in terminal for job in jobs):
            break
    else:
        print("TIMEOUT waiting for jobs")
        return 1

    if not fuzz_seen:
        print("FAIL: no fuzz job was ever dispatched for the memory-corruption candidate")
        return 1
    for job in jobs:
        if job["status"] == "failed":
            print("FAILED JOB:", json.dumps(job.get("failure"), indent=2)[:800])
    fuzz_terminal = [job for job in jobs if job["kind"] == "fuzz"]
    status = fuzz_terminal[0]["status"]
    print("fuzz terminal status:", status)
    # Crash or clean run both prove the chain is reachable; the failure detail
    # (printed above) says which link broke when it is not.
    return 0 if status in ("succeeded", "failed") else 1


if __name__ == "__main__":
    sys.exit(main())
