"""VulnWeaver 演示端到端驱动脚本。

用法（宿主机 Git Bash 或任何有 python3 + curl 的环境）:
    python scripts/demo_e2e.py --base-url http://127.0.0.1:8080 \
        --username owner --password '<密码>' \
        --sample code/tests/fixtures/packed-overflow-note/dist/packed-overflow-note \
        --project "演示-加壳溢出" --exploit

流程：登录 -> 配置模型（可选 --model-* 参数）-> 创建项目（可开利用验证）
-> 上传样本 -> 创建任务 -> 轮询任务/作业/发现 -> 导出报告到 --out 目录。
脚本只读样本文件并调用 HTTP API，不在宿主机执行任何样本。
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

TERMINAL = {"completed", "failed", "cancelled"}


class Client:
    def __init__(self, base_url: str) -> None:
        self.base = base_url.rstrip("/")
        self.cookie: str = ""
        self.csrf: str = ""

    def request(self, method: str, path: str, *, payload=None, headers=None, raw=None):
        url = self.base + path
        hdrs = {"Accept": "application/json"}
        if self.cookie:
            hdrs["Cookie"] = self.cookie
        if payload is not None or raw is not None:
            hdrs["X-CSRF-Token"] = self.csrf
        if headers:
            hdrs.update(headers)
        data = raw
        if payload is not None:
            data = json.dumps(payload).encode()
            hdrs["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                set_cookie = resp.headers.get("Set-Cookie")
                if set_cookie:
                    self.cookie = set_cookie.split(";")[0]
                body = resp.read()
                return resp.status, body
        except urllib.error.HTTPError as err:
            return err.code, err.read()

    def json(self, method: str, path: str, payload=None):
        status, body = self.request(method, path, payload=payload)
        try:
            return status, json.loads(body)
        except json.JSONDecodeError:
            return status, {"_raw": body.decode(errors="replace")}

    def upload(self, path: str, file_path: Path, filename: str):
        boundary = "----vulnweaver-demo"
        content = file_path.read_bytes()
        part = (
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
            f"filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        ).encode() + content + f"\r\n--{boundary}--\r\n".encode()
        status, body = self.request(
            "POST", path, raw=part,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        try:
            return status, json.loads(body)
        except json.JSONDecodeError:
            return status, {"_raw": body.decode(errors="replace")}


def wait_task(client: Client, task_id: str, deadline_s: int):
    started = time.time()
    last = None
    while time.time() - started < deadline_s:
        status, task = client.json("GET", f"/api/tasks/{task_id}")
        if status == 200:
            state = task.get("status")
            if state != last:
                print(f"[{int(time.time()-started):>4}s] 任务状态: {state}")
                last = state
            if state in TERMINAL:
                return task
        time.sleep(5)
    raise SystemExit(f"任务 {task_id} 在 {deadline_s}s 内未完成")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://127.0.0.1:8080")
    ap.add_argument("--username", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--sample", required=True, type=Path)
    ap.add_argument("--project", default="演示项目")
    ap.add_argument("--project-id", help="复用既有项目（跳过创建与模型配置）")
    ap.add_argument("--exploit", action="store_true", help="开启利用验证（动态链路）")
    ap.add_argument("--model-base-url", default=None)
    ap.add_argument("--model-name", default=None)
    ap.add_argument("--model-api-key", default=None)
    ap.add_argument("--out", type=Path, default=Path("demo-e2e-out"))
    ap.add_argument("--deadline", type=int, default=1800)
    args = ap.parse_args()

    c = Client(args.base_url)
    status, body = c.json("POST", "/api/auth/login", payload={
        "username": args.username, "password": args.password})
    if status != 200:
        # 全新安装则先注册
        status, body = c.json("POST", "/api/auth/register", payload={
            "username": args.username, "password": args.password})
        if status not in (200, 201):
            raise SystemExit(f"登录/注册失败: {status} {body}")
    print(f"已登录: {args.username}")

    if args.model_base_url and not args.project_id:
        status, body = c.json("PUT", "/api/settings", payload={
            "modelEndpoints": {
                "review": {"baseUrl": args.model_base_url, "modelName": args.model_name,
                            "apiKey": args.model_api_key},
                "planning": {"baseUrl": args.model_base_url, "modelName": args.model_name,
                              "apiKey": args.model_api_key},
                "audit": {"baseUrl": args.model_base_url, "modelName": args.model_name,
                           "apiKey": args.model_api_key},
            }})
        print(f"模型配置: HTTP {status}")
        if status not in (200, 201):
            print(f"  设置载荷可能不匹配当前契约，请核对 /api/settings schema: {json.dumps(body)[:400]}")

    project_id = args.project_id
    if not project_id:
        status, body = c.json("POST", "/api/projects", payload={
            "name": args.project, "exploit_validation_enabled": args.exploit})
        if status not in (200, 201):
            raise SystemExit(f"创建项目失败: {status} {body}")
        project_id = body["id"]
        print(f"项目: {project_id}")

    status, body = c.upload(
        f"/api/projects/{project_id}/artifacts", args.sample, args.sample.name)
    if status not in (200, 201):
        raise SystemExit(f"上传失败: {status} {body}")
    artifact_id = body["id"]
    print(f"工件: {artifact_id}")

    status, body = c.json("POST", f"/api/projects/{project_id}/tasks", payload={
        "artifact_id": artifact_id})
    if status not in (200, 201, 202):
        raise SystemExit(f"创建任务失败: {status} {body}")
    task_id = body["id"]
    print(f"任务: {task_id}")

    task = wait_task(c, task_id, args.deadline)

    status, jobs = c.json("GET", f"/api/tasks/{task_id}/jobs")
    for job in jobs if isinstance(jobs, list) else jobs.get("jobs", []):
        print(f"  job {job.get('kind'):<18} {job.get('status')}")
    status, findings = c.json("GET", f"/api/tasks/{task_id}/findings")
    items = findings if isinstance(findings, list) else findings.get("findings", [])
    print(f"发现 {len(items)} 个漏洞:")
    for f in items:
        print(f"  [{f.get('severity')}] {f.get('title')} ({f.get('cwe_id')}) "
              f"状态={f.get('status')} 置信度={f.get('confidence')}")

    args.out.mkdir(parents=True, exist_ok=True)
    status, body = c.json("POST", f"/api/tasks/{task_id}/reports", payload={"format": "markdown"})
    print(f"Markdown 报告 Job: HTTP {status}")
    # 报告 Job 异步生成；轮询报告列表并下载
    deadline = time.time() + 300
    while time.time() < deadline:
        status, reports = c.json("GET", f"/api/tasks/{task_id}/reports")
        entries = reports if isinstance(reports, list) else reports.get("reports", [])
        md = [r for r in entries if "markdown" in str(r.get("format", "")).lower()
              and r.get("status") == "succeeded"]
        if md:
            ref = md[0].get("artifact_version_id") or md[0].get("object_ref")
            st, raw = c.request("GET", f"/api/artifacts/{ref}/content")
            if st == 200 and ref:
                (args.out / f"{task_id}-report.md").write_bytes(raw)
                print(f"报告已保存: {args.out / (task_id + '-report.md')}")
            break
        time.sleep(5)
    (args.out / f"{task_id}-summary.json").write_text(
        json.dumps({"task": task, "findings": items}, ensure_ascii=False, indent=2),
        encoding="utf-8")
    print(f"任务结果: {task.get('status')} / {task.get('result')}")


if __name__ == "__main__":
    sys.exit(main())
