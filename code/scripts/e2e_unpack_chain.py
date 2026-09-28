"""In-network E2E: upload a custom XOR-packed ELF and drive the unpack chain.

Runs inside the compose control-plane network against the live api service.
Verifies: binary-import job succeeds, a derived xor-recovered-binary artifact
appears, and the analysis result points at the unpacked image.
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path

import httpx

from tests.binary_analysis.samples import elf64_sample, packed_elf64_sample

BASE = "http://api:8000"
USERNAME = "vw-e2e"
PASSWORD = "VwE2e-2026-Unpack-Chain"


def build_sample() -> tuple[bytes, bytes, str]:
    inner = elf64_sample()
    outer = bytearray(packed_elf64_sample(keep_sections=False, alphabet=256))
    outer[0x1000 : 0x1000 + len(inner)] = bytes(value ^ 0x5A for value in inner)
    return bytes(outer), inner, hashlib.sha256(inner).hexdigest()


def main() -> int:
    client = httpx.Client(base_url=BASE, timeout=60.0)
    outer, inner, inner_digest = build_sample()

    register = client.post(
        "/api/auth/register",
        json={"schema_version": "1.0.0", "username": USERNAME, "password": PASSWORD},
    )
    if register.status_code not in (200, 201):
        print("register responded:", register.status_code, register.text[:300])
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
    print("authenticated as", USERNAME)

    settings = client.get("/api/settings").json()
    if not settings.get("review_model_name"):
        # secrets/model_api_key.txt carries three lines: base_url, model, key.
        base_url, model_name, api_key = (
            Path("/src/secrets/model_api_key.txt").read_text(encoding="utf-8").splitlines()[:3]
        )
        update = client.put(
            "/api/settings",
            headers={**write_headers, "Idempotency-Key": f"settings-{int(time.time())}"},
            json={
                "schema_version": "1.0.0",
                "review_model_base_url": base_url,
                "review_model_name": model_name,
                "review_model_context_window_tokens": 64000,
                "review_model_api_key": api_key,
            },
        )
        if update.status_code >= 400:
            print("settings responded:", update.status_code, update.text[:300])
        update.raise_for_status()
        print("review model configured")
    else:
        print("review model already configured:", settings.get("review_model_name"))

    project = client.post(
        "/api/projects",
        json={
            "schema_version": "1.0.0",
            "name": f"unpack-e2e-{int(time.time())}",
            "input_scope": ["local-sample"],
            "permission_mode": "request_permission",
            "exploit_validation_enabled": False,
        },
        headers={**write_headers, "Idempotency-Key": f"proj-{int(time.time())}"},
    )
    if project.status_code >= 400:
        print("project responded:", project.status_code, project.text[:300])
    project.raise_for_status()
    project_id = project.json()["id"]
    print("project:", project_id)

    upload = client.post(
        f"/api/projects/{project_id}/artifacts",
        params={"kind": "elf"},
        headers={
            **write_headers,
            "Idempotency-Key": f"upload-{int(time.time())}",
            "X-Artifact-Filename": "xor-packed-sample.bin",
            "Content-Type": "application/octet-stream",
        },
        content=outer,
    )
    if upload.status_code >= 400:
        print("upload responded:", upload.status_code, upload.text[:400])
    upload.raise_for_status()
    detail = upload.json()
    version_id = detail["versions"][0]["id"]
    print("uploaded artifact version:", version_id)

    task = client.post(
        f"/api/projects/{project_id}/tasks",
        headers={**write_headers, "Idempotency-Key": f"task-{int(time.time())}"},
        json={"schema_version": "1.0.0", "artifact_version_ids": [version_id]},
    )
    task.raise_for_status()
    task_id = task.json()["id"]
    print("task:", task_id)

    terminal = {"succeeded", "failed", "cancelled"}
    jobs = []
    for attempt in range(120):
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
            print("FAILED JOB:", json.dumps(job, indent=2)[:2000])

    listing = client.get(f"/api/projects/{project_id}/artifacts")
    listing.raise_for_status()
    derived = []
    for listed in listing.json():
        detail_response = client.get(
            f"/api/projects/{project_id}/artifacts/{listed['id']}"
        )
        detail_response.raise_for_status()
        item = detail_response.json()
        artifact = item["artifact"]
        for version in item["versions"]:
            config = version.get("generation_config") or {}
            derived.append(
                {
                    "kind": artifact["kind"],
                    "version_id": version["id"],
                    "parent": version.get("parent_version_id"),
                    "format": config.get("format"),
                    "tool": config.get("tool"),
                    "methods": config.get("methods"),
                    "digest": version.get("digest"),
                }
            )
    print("derived artifacts:")
    print(json.dumps(derived, indent=2))

    recovered = [
        item
        for item in derived
        if item["format"] == "xor-recovered-binary"
    ]
    if not recovered:
        print("FAIL: no xor-recovered-binary derived artifact")
        return 1
    if str(recovered[0]["digest"]).removeprefix("sha256:") != inner_digest:
        print("FAIL: recovered digest mismatch")
        print("expected:", inner_digest)
        print("actual:  ", recovered[0]["digest"])
        return 1

    import_jobs = [job for job in jobs if job["kind"] == "import"]
    if not import_jobs or import_jobs[0]["status"] != "succeeded":
        print("FAIL: binary-import job did not succeed")
        for job in import_jobs or jobs:
            print(json.dumps(job, indent=2)[:2000])
        return 1
    print("binary-import: succeeded")
    audit_jobs = [job for job in jobs if job["kind"] == "semantic_audit"]
    print("semantic_audit:", audit_jobs[0]["status"] if audit_jobs else "not scheduled")
    analysis = [
        item for item in derived if item["format"] == "binary-analysis-result"
    ]
    if not analysis:
        print("FAIL: no binary-analysis-result artifact (import job may have failed)")
        for job in jobs:
            print(json.dumps(job, indent=2)[:2000])
        return 1
    print("analysis parent is recovered image:",
          analysis[0]["parent"] == recovered[0]["version_id"])
    if analysis[0]["parent"] != recovered[0]["version_id"]:
        print("FAIL: analysis did not switch to the unpacked image")
        return 1

    print("E2E OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
