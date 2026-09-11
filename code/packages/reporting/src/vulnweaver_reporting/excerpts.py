"""Resolve report excerpts through task-scoped immutable versions and PAIR."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable, Sequence

from vulnweaver_contracts import ArtifactVersion, Finding, PairFunction, SourceLocation, Task
from vulnweaver_persistence import Database, EntityNotFound, Repositories

from vulnweaver_reporting.context import CodeExcerpt

SourceCodeReader = Callable[[ArtifactVersion, SourceLocation], CodeExcerpt]
_TOTAL_BYTES = 2 * 1024 * 1024


def bounded_excerpt(excerpt: CodeExcerpt) -> CodeExcerpt:
    original = excerpt["text"]
    text = (
        "\n".join(original.splitlines()[:80]).encode()[: 16 * 1024].decode("utf-8", errors="ignore")
    )
    safe_text = re.sub(
        r"""(?i)(\b\w{0,128}(?:password|passwd|secret|api_?key|token)\w{0,128}["']?\s*[:=]\s*)"""
        r"""(["'])(?:\\.|(?!\2)[^\\\r\n])*(?:\2|$)""",
        r"\1\2[已脱敏]\2",
        text,
    )
    return CodeExcerpt(
        text=safe_text,
        label=excerpt["label"] + ("（常见凭据赋值已脱敏）" if text != safe_text else ""),
        source=excerpt["source"],
        first_line=max(1, excerpt["first_line"]),
        truncated=excerpt["truncated"]
        or len(original.splitlines()) > 80
        or len(original.encode()) > 16 * 1024,
    )


async def task_version(
    repositories: Repositories,
    task: Task,
    version_id: str,
) -> ArtifactVersion:
    """Accept the task's input or a same-project descendant; never current_version."""
    version = await repositories.artifacts.get_version(version_id)
    cursor = version
    seen: set[str] = set()
    while len(seen) < 64 and cursor["id"] not in seen:
        seen.add(cursor["id"])
        artifact = await repositories.artifacts.get(cursor["artifact_id"])
        if artifact["project_id"] != task["project_id"]:
            break
        if cursor["id"] in task["artifact_version_ids"]:
            return version
        parent = cursor.get("parent_version_id")
        if not parent:
            break
        cursor = await repositories.artifacts.get_version(parent)
    raise ValueError("report.source_outside_task")


async def collect_excerpts(
    database: Database,
    task: Task,
    findings: Sequence[Finding],
    reader: SourceCodeReader | None,
) -> tuple[dict[str, CodeExcerpt], dict[str, str]]:
    excerpts: dict[str, CodeExcerpt] = {}
    errors: dict[str, str] = {}
    source_requests: list[tuple[Finding, ArtifactVersion, SourceLocation]] = []
    remaining = _TOTAL_BYTES
    async with database.transaction() as repositories:
        for finding in findings:
            location = finding["location"]
            version_id = location["artifact_version_id"]
            try:
                version = await task_version(repositories, task, version_id)
            except EntityNotFound:
                errors[finding["id"]] = "来源版本已不可用"
                continue
            if "path" in location:
                if reader is not None:
                    source_requests.append((finding, version, location))
                else:
                    errors[finding["id"]] = "源码摘录读取器未配置"
                continue
            # PAIR is indexed by the submitted image, while binary locations may
            # point at its unpacked descendant. Require an exact analyzed-version
            # match; equal addresses in another image are not interchangeable.
            functions: list[PairFunction] = []
            for graph_version in dict.fromkeys([version_id, *task["artifact_version_ids"]]):
                matches = await repositories.pair.functions_at_address(
                    graph_version, location["virtual_address"]
                )
                functions.extend(
                    function
                    for function in matches
                    if function["binary_location"] is not None
                    and function["binary_location"]["artifact_version_id"] == version_id
                    and function["attributes"].get("analyzed_artifact_version_id", version_id)
                    == version_id
                )
            for function in functions:
                raw = function["attributes"].get("pseudocode")
                candidates = raw if isinstance(raw, list) else []
                for candidate in candidates:
                    if not isinstance(candidate, dict):
                        continue
                    code = candidate.get("text")
                    if not isinstance(code, str):
                        continue
                    excerpt = CodeExcerpt(
                        text=code,
                        label="工具反编译伪代码（非原始源码）",
                        source=(
                            f"{version_id} · {function['id']} · {version['digest']}"
                            f" · {candidate.get('tool_name', '反编译器')}"
                        ),
                        first_line=1,
                        truncated=False,
                    )
                    bounded = bounded_excerpt(excerpt)
                    size = len(bounded["text"].encode())
                    if size <= remaining:
                        excerpts[finding["id"]] = bounded
                        remaining -= size
                    else:
                        errors[finding["id"]] = "报告摘录总预算已用尽；位置与证据仍保留"
                    break
                if finding["id"] in excerpts:
                    break
            if finding["id"] not in excerpts and finding["id"] not in errors:
                errors[finding["id"]] = "该地址没有已登记的工具伪代码"
    # Archive/CAS I/O deliberately happens after the database transaction closes.
    for finding, version, source_location in source_requests:
        assert reader is not None
        if remaining <= 0:
            errors[finding["id"]] = "报告摘录总预算已用尽；位置与证据仍保留"
            continue
        try:
            bounded = bounded_excerpt(await asyncio.to_thread(reader, version, source_location))
            size = len(bounded["text"].encode())
            if size <= remaining:
                excerpts[finding["id"]] = bounded
                remaining -= size
            else:
                errors[finding["id"]] = "报告摘录总预算已用尽；位置与证据仍保留"
        except (OSError, ValueError) as error:
            errors[finding["id"]] = f"源码摘录不可用（{type(error).__name__}）"
    return excerpts, errors
