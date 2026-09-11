"""VulnWeaver 演示端到端驱动脚本。

用法（宿主机 Git Bash 或任何有 python3 的环境）:
    python scripts/demo_e2e.py --base-url http://127.0.0.1:8080 \
        --username owner --password '<密码>' \
        --sample code/tests/fixtures/packed-overflow-note/dist/packed-overflow-note \
        --project "演示-加壳溢出" --exploit \
        --model-base-url https://api.deepseek.com --model-name deepseek-v4-pro \
        --model-api-key '<key>'

流程：登录 -> 检查/配置模型（可选 --model-* 参数）-> 创建项目（可开利用验证）
-> 上传样本（ELF 直传 / 源码自动打包 zip）-> 创建任务 -> 轮询任务/作业/发现
-> 生成并下载报告到 --out 目录。
脚本只读样本文件并调用 HTTP API，不在宿主机执行任何样本。

请求契约对齐 apps/api（schemas.py）：
- 所有 JSON 请求体携带 schema_version="1.0.0"；
- 写操作带 X-CSRF-Token 与 Idempotency-Key 请求头；
- 上传使用 application/octet-stream 原始字节流（非 multipart）；
- 报告 Job 以样本工件（artifact_id + version_id）作为报告源。
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from pathlib import Path

SCHEMA_VERSION = "1.0.0"
TERMINAL_TASK = {"completed", "failed", "cancelled"}
TERMINAL_JOB = {"succeeded", "failed", "cancelled"}


def safe_name(identifier: str) -> str:
    """Task IDs contain ':' which NTFS treats as an Alternate Data Stream."""
    return identifier.replace(":", "_")


class ApiError(SystemExit):
    pass


class Client:
    def __init__(self, base_url: str) -> None:
        self.base = base_url.rstrip("/")
        self.cookies: dict[str, str] = {}
        self.csrf: str = ""

    @staticmethod
    def _idempotency_key() -> str:
        return uuid.uuid4().hex

    def request(self, method: str, path: str, *, payload=None, headers=None, raw=None, query=None):
        url = self.base + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        hdrs = {"Accept": "application/json"}
        cookie = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if cookie:
            hdrs["Cookie"] = cookie
        if payload is not None or raw is not None:
            hdrs["X-CSRF-Token"] = self.csrf
            hdrs["Idempotency-Key"] = self._idempotency_key()
        if headers:
            hdrs.update(headers)
        data = raw
        if payload is not None:
            data = json.dumps(payload).encode()
            hdrs["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                for set_cookie in resp.headers.get_all("Set-Cookie") or []:
                    pair = set_cookie.split(";", 1)[0]
                    if "=" in pair:
                        name, _, value = pair.partition("=")
                        self.cookies[name.strip()] = value.strip()
                body = resp.read()
                return resp.status, body
        except urllib.error.HTTPError as err:
            return err.code, err.read()

    def json(self, method: str, path: str, payload=None, *, query=None):
        status, body = self.request(method, path, payload=payload, query=query)
        try:
            return status, json.loads(body)
        except json.JSONDecodeError:
            return status, {"_raw": body.decode(errors="replace")}

    def upload(self, path: str, file_path: Path, filename: str, kind: str):
        """按 API 契约上传原始字节流（application/octet-stream）。"""
        status, body = self.request(
            "POST", path, raw=file_path.read_bytes(),
            query={"kind": kind},
            headers={
                "Content-Type": "application/octet-stream",
                "X-Artifact-Filename": urllib.parse.quote(filename),
            },
        )
        try:
            return status, json.loads(body)
        except json.JSONDecodeError:
            return status, {"_raw": body.decode(errors="replace")}


def detect_kind(sample: Path) -> tuple[str, Path]:
    """ELF/PE 直传；其余打包为 zip 源码压缩包（source_archive 要求归档魔数）。"""
    head = sample.read_bytes()[:8]
    if head.startswith(b"\x7fELF"):
        return "elf", sample
    if head.startswith(b"MZ"):
        return "pe", sample
    bundle = Path(tempfile.mkdtemp(prefix="vulnweaver-demo-")) / (sample.stem + ".zip")
    with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.write(sample, arcname=sample.name)
    return "source_archive", bundle


def configure_model(client: Client, args) -> None:
    """GET -> 合并 -> PUT：PUT 是整体替换，只发部分字段会把其余设置重置为默认值。"""
    status, current = client.json("GET", "/api/settings")
    if status != 200:
        raise SystemExit(f"读取设置失败: {status} {current}")
    base_url = (args.model_base_url or "").strip()
    model_name = (args.model_name or "").strip()
    if not base_url or not model_name:
        raise SystemExit("配置模型需要 --model-base-url 与 --model-name")
    payload = {
        "schema_version": SCHEMA_VERSION,
        "review_model_base_url": base_url,
        "review_model_name": model_name,
        "review_model_api_key": args.model_api_key,
        "clear_review_model_api_key": False,
        # 清空分层配置，让 planning/audit/review 回退到上方的 review 模型设置，
        # 避免历史残留的分层端点覆盖本次配置。
        "model_tiers": {
            tier: {"protocol": "openai", "base_url": "", "model_name": "",
                   "context_window_tokens": 0, "thinking_mode": "off",
                   "thinking_budget_tokens": 0, "timeout_seconds": 0, "max_attempts": 0}
            for tier in ("planning", "audit", "review", "report")
        },
        "clear_tier_api_keys": ["planning", "audit", "review", "report"],
    }
    status, body = client.json("PUT", "/api/settings", payload=payload)
    print(f"模型配置: HTTP {status}")
    if status != 200:
        raise SystemExit(f"写入模型设置失败: {json.dumps(body, ensure_ascii=False)[:400]}")
    print(f"  review 模型: {body.get('review_model_base_url')} / {body.get('review_model_name')} "
          f"key_configured={body.get('api_key_configured')}")


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
            if state in TERMINAL_TASK:
                return task
        time.sleep(5)
    raise SystemExit(f"任务 {task_id} 在 {deadline_s}s 内未完成")


def wait_report_job(client: Client, task_id: str, deadline_s: int = 300):
    deadline = time.time() + deadline_s
    while time.time() < deadline:
        status, jobs = client.json("GET", f"/api/tasks/{task_id}/jobs")
        if status == 200:
            entries = jobs if isinstance(jobs, list) else jobs.get("jobs", [])
            reports = [j for j in entries if str(j.get("kind")) == "report"]
            for job in reports:
                if job.get("status") in TERMINAL_JOB:
                    return job
        time.sleep(5)
    return None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://127.0.0.1:8080")
    ap.add_argument("--username", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--sample", required=True, type=Path)
    ap.add_argument("--project", default="演示项目")
    ap.add_argument("--project-id", help="复用既有项目（跳过创建与模型配置）")
    ap.add_argument("--input-scope", default="本地自编教学样本（静态审计与容器内动态验证）")
    ap.add_argument("--exploit", action="store_true", help="开启利用验证（动态链路）")
    ap.add_argument("--permission-mode", choices=["full_access", "request_permission"],
                    default="full_access")
    ap.add_argument("--model-base-url", default=None)
    ap.add_argument("--model-name", default=None)
    ap.add_argument("--model-api-key", default=None)
    ap.add_argument("--formats", default="markdown", help="逗号分隔: markdown,pdf,sarif")
    ap.add_argument("--out", type=Path, default=Path("demo-e2e-out"))
    ap.add_argument("--deadline", type=int, default=1800)
    args = ap.parse_args()

    c = Client(args.base_url)
    status, body = c.json("POST", "/api/auth/login", payload={
        "schema_version": SCHEMA_VERSION,
        "username": args.username, "password": args.password})
    if status != 200:
        # 全新安装则先注册
        status, body = c.json("POST", "/api/auth/register", payload={
            "schema_version": SCHEMA_VERSION,
            "username": args.username, "password": args.password})
        if status not in (200, 201):
            raise SystemExit(f"登录/注册失败: {status} {body}")
    c.csrf = body.get("csrf_token", "")
    print(f"已登录: {args.username}")

    if args.model_base_url and not args.project_id:
        configure_model(c, args)

    project_id = args.project_id
    if not project_id:
        status, body = c.json("POST", "/api/projects", payload={
            "schema_version": SCHEMA_VERSION,
            "name": args.project,
            "input_scope": [args.input_scope],
            "permission_mode": args.permission_mode,
            "exploit_validation_enabled": args.exploit})
        if status not in (200, 201):
            raise SystemExit(f"创建项目失败: {status} {body}")
        project_id = body["id"]
        print(f"项目: {project_id}")

    status, project = c.json("GET", f"/api/projects/{project_id}")
    if status != 200:
        raise SystemExit(f"读取项目失败: {status} {project}")

    kind, bundle = detect_kind(args.sample)
    status, body = c.upload(
        f"/api/projects/{project_id}/artifacts", bundle, bundle.name, kind)
    if status not in (200, 201):
        raise SystemExit(f"上传失败: {status} {body}")
    artifact_id = body["artifact"]["id"]
    version_id = body["artifact"]["current_version_id"]
    print(f"工件: {artifact_id} (kind={kind}, version={version_id})")

    status, body = c.json("POST", f"/api/projects/{project_id}/tasks", payload={
        "schema_version": SCHEMA_VERSION,
        "artifact_version_ids": [version_id],
        "resource_budget": project["resource_budget"]})
    if status not in (200, 201):
        raise SystemExit(f"创建任务失败: {status} {body}")
    task_id = body["id"]
    print(f"任务: {task_id}")

    started = time.time()
    task = wait_task(c, task_id, args.deadline)
    elapsed = int(time.time() - started)

    status, jobs = c.json("GET", f"/api/tasks/{task_id}/jobs")
    job_entries = jobs if isinstance(jobs, list) else jobs.get("jobs", [])
    for job in job_entries:
        failure = job.get("failure")
        suffix = ""
        if failure:
            suffix = f"  failure={failure.get('code')}: {str(failure.get('message'))[:160]}"
        print(f"  job {str(job.get('kind')):<18} {job.get('status')}{suffix}")

    status, findings = c.json("GET", f"/api/tasks/{task_id}/findings")
    items = findings if isinstance(findings, list) else findings.get("findings", [])
    print(f"发现 {len(items)} 个漏洞:")
    for f in items:
        print(f"  [{f.get('severity')}] {f.get('title')} ({f.get('cwe_id')}) "
              f"状态={f.get('status')} 置信度={f.get('confidence')}")

    args.out.mkdir(parents=True, exist_ok=True)
    for fmt in [f.strip() for f in args.formats.split(",") if f.strip()]:
        status, body = c.json("POST", f"/api/tasks/{task_id}/reports", payload={
            "schema_version": SCHEMA_VERSION,
            "artifact_id": artifact_id,
            "version_id": version_id,
            "format": fmt})
        detail = "" if status == 202 else json.dumps(body, ensure_ascii=False)[:300]
        print(f"{fmt} 报告 Job: HTTP {status} {detail}")

    reports = {}
    job = wait_report_job(c, task_id)
    if job and job.get("status") == "succeeded":
        status, reports_list = c.json("GET", f"/api/tasks/{task_id}/jobs")
        entries = reports_list if isinstance(reports_list, list) else reports_list.get("jobs", [])
        report_jobs = [j for j in entries
                       if str(j.get("kind")) == "report" and j.get("status") == "succeeded"]
        for job in report_jobs:
            arguments = job.get("arguments") or {}
            report_artifact = arguments.get("artifact_id")
            report_version = arguments.get("version_id")
            fmt = str(arguments.get("format"))
            st, raw = c.request("GET", f"/api/artifacts/{report_artifact}/content",
                                query={"version_id": report_version})
            if st == 200:
                ext = {"markdown": "md", "pdf": "pdf", "sarif": "sarif"}.get(fmt, fmt)
                target = args.out / f"{safe_name(task_id)}-report.{ext}"
                target.write_bytes(raw)
                reports[fmt] = str(target)
                print(f"报告已保存: {target}")
    else:
        print("报告 Job 未成功完成（见上方 job 列表）")

    (args.out / f"{safe_name(task_id)}-summary.json").write_text(
        json.dumps({"project": project, "task": task, "jobs": job_entries,
                    "findings": items, "reports": reports,
                    "elapsed_seconds": elapsed},
                   ensure_ascii=False, indent=2),
        encoding="utf-8")
    print(f"任务结果: {task.get('status')} / {task.get('result')} （耗时 {elapsed}s）")
    print(f"汇总已保存: {args.out / (safe_name(task_id) + '-summary.json')}")


if __name__ == "__main__":
    sys.exit(main())
