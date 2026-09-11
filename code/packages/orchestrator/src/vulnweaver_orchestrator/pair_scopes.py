"""Shared resolution of the artifact versions that hold a task's PAIR graphs.

The two pipelines scope differently.  Source functions are keyed to the
artifact version the task imported; binary functions are keyed to the image
the analysis actually read -- the unpacked one when the input was packed --
which is the parent of the binary-import Job's ``binary-analysis-result``
output and therefore absent from ``task.artifact_version_ids``.  Every audit
entry point must resolve this same scope, or packed samples silently audit
zero functions.
"""

from __future__ import annotations

from vulnweaver_contracts import Task
from vulnweaver_persistence import Repositories

BINARY_IMPORT_TOOL = "binary-import"


async def pair_version_scope(repositories: Repositories, task: Task) -> list[str]:
    """Task artifact versions plus the versions binary analysis actually read.

    Mirrors the API workbench's ``_pair_scopes``: the derived analysis version
    is recovered from the binary-import Job's ``binary-analysis-result`` output
    via its ``parent_version_id``.
    """

    resolved = list(task["artifact_version_ids"])
    for job in await repositories.jobs.list_for_task(task["id"]):
        tool = job.get("tool")
        if not (isinstance(tool, dict) and tool.get("name") == BINARY_IMPORT_TOOL):
            continue
        result = await repositories.jobs.get_result(job["id"])
        if result is None:
            continue
        for version_id in result["produced_artifact_version_ids"]:
            version = await repositories.artifacts.get_version(version_id)
            config = version.get("generation_config") or {}
            if config.get("format") != "binary-analysis-result":
                continue
            parent = version.get("parent_version_id")
            if isinstance(parent, str) and parent and parent not in resolved:
                resolved.append(parent)
    return sorted(resolved)
