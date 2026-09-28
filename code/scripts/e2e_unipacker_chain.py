"""In-network E2E: a real UPX shell with defaced fingerprints through unipacker.

Runs inside the compose control-plane network against the live api service.
The sample is a genuine UPX-packed win64/pe whose UPX fingerprints were renamed
so `upx -d` refuses it; the chain must fall through to emulated unpacking and
publish an emulated-unpacked-binary derived artifact that the analysis then
targets.  Sample path: /samples/upx-defaced.exe (see DEVELOPMENT_STATUS).
"""

from __future__ import annotations

import hashlib
import json
import sys
import time

import httpx

BASE = "http://api:8000"
USERNAME = "vw-e2e"
PASSWORD = "VwE2e-2026-Unpack-Chain"
SAMPLE = "/samples/upx-defaced-decoy.exe"


def main() -> int:
    client = httpx.Client(base_url=BASE, timeout=60.0)
    with open(SAMPLE, "rb") as stream:
        sample = stream.read()
    packed_digest = hashlib.sha256(sample).hexdigest()
    print("packed sample sha256:", packed_digest)

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
    csrf = payload["csrf_token"]
    write_headers = {"X-CSRF-Token": csrf}

    project = client.post(
        "/api/projects",
        headers={**write_headers, "Idempotency-Key": f"proj-u-{int(time.time())}"},
        json={
            "schema_version": "1.0.0",
            "name": f"unipacker-e2e-{int(time.time())}",
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
        params={"kind": "pe"},
        headers={
            **write_headers,
            "Idempotency-Key": f"upload-u-{int(time.time())}",
            "X-Artifact-Filename": "upx-defaced.exe",
            "Content-Type": "application/octet-stream",
        },
        content=sample,
    )
    if upload.status_code >= 400:
        print("upload responded:", upload.status_code, upload.text[:300])
    upload.raise_for_status()
    version_id = upload.json()["versions"][0]["id"]
    print("uploaded artifact version:", version_id)

    task = client.post(
        f"/api/projects/{project_id}/tasks",
        headers={**write_headers, "Idempotency-Key": f"task-u-{int(time.time())}"},
        json={"schema_version": "1.0.0", "artifact_version_ids": [version_id]},
    )
    task.raise_for_status()
    task_id = task.json()["id"]
    print("task:", task_id)

    terminal = {"succeeded", "failed", "cancelled"}
    jobs: list[dict[str, object]] = []
    for attempt in range(150):
        time.sleep(5)
        jobs_response = client.get(f"/api/tasks/{task_id}/jobs")
        jobs_response.raise_for_status()
        jobs = jobs_response.json()
        summary = {job["kind"]: job["status"] for job in jobs}
        print(f"[poll {attempt}] {summary}")
        if jobs and all(job["status"] in terminal for job in jobs):
            break
    else:
        print("TIMEOUT waiting for jobs to settle")
        return 1

    for job in jobs:
        if job["status"] == "failed":
            print("FAILED JOB:", json.dumps(job, indent=2)[:1500])

    listing = client.get(f"/api/projects/{project_id}/artifacts")
    listing.raise_for_status()
    derived = []
    for listed in listing.json():
        detail = client.get(f"/api/projects/{project_id}/artifacts/{listed['id']}")
        detail.raise_for_status()
        item = detail.json()
        for version in item["versions"]:
            config = version.get("generation_config") or {}
            derived.append(
                {
                    "kind": item["artifact"]["kind"],
                    "version_id": version["id"],
                    "parent": version.get("parent_version_id"),
                    "format": config.get("format"),
                    "tool": config.get("tool"),
                    "methods": config.get("methods"),
                    "digest": version.get("digest"),
                }
            )
    print(json.dumps(derived, indent=2))

    emulated = [item for item in derived if item["format"] == "emulated-unpacked-binary"]
    if not emulated:
        print("FAIL: no emulated-unpacked-binary derived artifact (unipacker path)")
        return 1
    if emulated[0]["digest"] == f"sha256:{packed_digest}":
        print("FAIL: unpacked artifact is byte-identical to the packed input")
        return 1
    import_jobs = [job for job in jobs if job["kind"] == "import"]
    if not import_jobs or import_jobs[0]["status"] != "succeeded":
        print("FAIL: import job did not succeed")
        return 1
    analysis = [item for item in derived if item["format"] == "binary-analysis-result"]
    if not analysis:
        print("FAIL: no binary-analysis-result artifact")
        return 1
    if analysis[0]["parent"] != emulated[0]["version_id"]:
        print("FAIL: analysis did not target the emulated-unpacked image")
        return 1
    print("methods:", emulated[0]["methods"])
    print("E2E OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
