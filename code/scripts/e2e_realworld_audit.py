"""In-network E2E: submit a RealWorld acceptance sample (R1 source-audit track).

Uploads one registered realworld fixture (see ``tests/fixtures/realworld/README.md``)
to a fresh opt-in project, submits the audit task, and follows the pipeline to
its terminal state, printing every job transition and the findings that survive
anchoring.  Pass/fail against the truth anchors is judged by the caller (the
anchors are grader-only and must never enter agent-visible context).

Usage (host or dev container)::

    python e2e_realworld_audit.py ARCHIVE \
        --base-url http://api:8000 --project-name "RW：FFmpeg-8.1.2" \
        --poll-seconds 30 --max-polls 1200

The script only observes; it never injects the README's truth anchors anywhere.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import httpx

USERNAME = "vw-e2e"
PASSWORD = "VwE2e-2026-Unpack-Chain"
TERMINAL = {"succeeded", "failed", "cancelled"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path, help="path to the source archive to upload")
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--project-name", default=None)
    parser.add_argument(
        "--project-id",
        default=None,
        help="reuse an existing project (keeps the investigation-memory chain alive); "
        "omit to create a fresh one",
    )
    parser.add_argument(
        "--kind", default="source_archive", help="artifact kind (source_archive/elf/pe)"
    )
    parser.add_argument("--poll-seconds", type=float, default=30.0)
    parser.add_argument("--max-polls", type=int, default=1440)
    parser.add_argument("--submit-only", action="store_true", help="exit after task creation")
    parser.add_argument("--task-id", default=None, help="resume polling an existing task")
    args = parser.parse_args()

    client = httpx.Client(base_url=args.base_url, timeout=300.0)
    login = client.post(
        "/api/auth/login",
        json={"schema_version": "1.0.0", "username": USERNAME, "password": PASSWORD},
    )
    login.raise_for_status()
    headers = {"X-CSRF-Token": login.json()["csrf_token"]}
    stamp = int(time.time())

    if args.task_id:
        task_id = args.task_id
        print("resuming task:", task_id)
        jobs_response = client.get(f"/api/tasks/{task_id}/jobs")
        jobs_response.raise_for_status()
    else:
        if args.project_id:
            project_id = args.project_id
            print("reusing project:", project_id)
        else:
            project = client.post(
                "/api/projects",
                headers={**headers, "Idempotency-Key": f"proj-rw-{stamp}"},
                json={
                    "schema_version": "1.0.0",
                    "name": args.project_name or f"realworld-{stamp}",
                    "input_scope": ["local-sample"],
                    "permission_mode": "request_permission",
                    # Dynamic-verification opt-in: fuzz oracle, sandbox-command.
                    "exploit_validation_enabled": True,
                },
            )
            project.raise_for_status()
            project_id = project.json()["id"]
            print("project:", project_id)

        upload = client.post(
            f"/api/projects/{project_id}/artifacts",
            params={"kind": args.kind},
            headers={
                **headers,
                "Idempotency-Key": f"upload-rw-{stamp}",
                "X-Artifact-Filename": args.archive.name,
                "Content-Type": "application/octet-stream",
            },
            content=args.archive.read_bytes(),
        )
        if upload.status_code >= 400:
            print("upload failed:", upload.status_code, upload.text[:500])
            return 1
        version_id = upload.json()["versions"][0]["id"]
        print("uploaded version:", version_id)

        task = client.post(
            f"/api/projects/{project_id}/tasks",
            headers={**headers, "Idempotency-Key": f"task-rw-{stamp}"},
            json={"schema_version": "1.0.0", "artifact_version_ids": [version_id]},
        )
        task.raise_for_status()
        task_id = task.json()["id"]
        print("task:", task_id)
        if args.submit_only:
            return 0

    seen: dict[str, str] = {}
    jobs: list[dict[str, object]] = []
    consecutive_errors = 0
    for poll in range(args.max_polls):
        jobs_response = client.get(f"/api/tasks/{task_id}/jobs")
        # A transient gateway/API hiccup must not kill a hours-long watch:
        # retry with backoff and only give up after repeated failures.
        if jobs_response.status_code >= 500 or jobs_response.status_code == 401:
            consecutive_errors += 1
            if consecutive_errors >= 5:
                jobs_response.raise_for_status()
            print(f"[poll {poll}] jobs poll got {jobs_response.status_code}; retrying")
            time.sleep(args.poll_seconds)
            continue
        jobs_response.raise_for_status()
        payload = jobs_response.json()
        if not isinstance(payload, list):
            consecutive_errors += 1
            if consecutive_errors >= 5:
                raise RuntimeError(f"unexpected jobs payload: {str(payload)[:200]}")
            print(f"[poll {poll}] unexpected jobs payload; retrying")
            time.sleep(args.poll_seconds)
            continue
        consecutive_errors = 0
        jobs = payload
        summary = {}
        for job in jobs:
            state = f"{job['status']}/{job.get('outcome_code') or ''}"
            key = f"{job['kind']}#{job['id'][-8:]}"
            if seen.get(key) != state:
                print(f"[poll {poll}] {job['kind']} {job['id']} -> {state}")
                seen[key] = state
            summary[job["kind"]] = job["status"]
        if jobs and all(job["status"] in TERMINAL for job in jobs):
            break
        time.sleep(args.poll_seconds)
    else:
        print("TIMEOUT: jobs still running after max polls")
        return 1

    for job in jobs:
        if job["status"] == "failed":
            print("FAILED JOB:", job["kind"], json.dumps(job.get("failure"), indent=2)[:1200])

    findings = client.get(f"/api/tasks/{task_id}/findings").json()
    rows = (
        findings
        if isinstance(findings, list)
        else findings.get("findings", findings.get("items", []))
    )
    print(f"findings: {len(rows)}")
    for finding in rows:
        location = finding.get("location", {})
        print(
            "-",
            finding.get("id"),
            "|",
            finding.get("category"),
            finding.get("cwe_id"),
            "|",
            finding.get("status"),
            "|",
            location.get("path"),
            location.get("start_line"),
            "|",
            str(finding.get("title"))[:100],
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
