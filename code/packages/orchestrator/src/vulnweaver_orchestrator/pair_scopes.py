"""Shared resolution of the artifact versions that hold a task's PAIR graphs.

The two pipelines scope differently.  Source functions are keyed to the
artifact version the task imported; binary functions are keyed to the image
the analysis actually read -- the unpacked one when the input was packed --
which is the parent of the binary-import Job's ``binary-analysis-result``
output and therefore absent from ``task.artifact_version_ids``.  Every audit
entry point and the API workbench must resolve this same scope, or packed
samples silently audit zero functions and the workbench shows a different
world than the auditor anchored against.
"""

from __future__ import annotations

from collections.abc import Iterable

from vulnweaver_contracts import ArtifactKind, Task
from vulnweaver_persistence import Repositories

BINARY_IMPORT_TOOL = "binary-import"

SOURCE_KINDS = (ArtifactKind.SOURCE_ARCHIVE, ArtifactKind.SOURCE_REPOSITORY)
BINARY_KINDS = (ArtifactKind.ELF, ArtifactKind.PE, ArtifactKind.DERIVED)


def choose_pair_scope(
    scoped: Iterable[tuple[str, ArtifactKind, bool]],
) -> tuple[str, str]:
    """Pick the versions an audit anchors its findings to, in scope order.

    ``scoped`` yields ``(version_id, kind, has_functions)``. A source finding
    anchors to the first source version; a binary finding to the version that
    actually carries the PAIR graph, since a packed input's graph lives on the
    derived analysis version rather than on the uploaded image.

    This lives here, with the scope itself, because every entry point has to
    agree on it: the code-read proof authorizes a report against the version
    ``_resolve_location`` will anchor it to, so any second copy of the rule that
    drifts silently authorizes the wrong file (CR-06). Callers keep their own
    queries -- only the decision is shared.
    """
    source_version_id = ""
    binary_version_id = ""
    for version_id, kind, has_functions in scoped:
        if kind in SOURCE_KINDS:
            source_version_id = source_version_id or version_id
        elif kind in BINARY_KINDS and (has_functions or not binary_version_id):
            binary_version_id = version_id
    return source_version_id, binary_version_id


async def pair_version_scope(repositories: Repositories, task: Task) -> list[str]:
    """Task artifact versions plus the versions binary analysis actually read.

    The single scope resolution for every consumer: the audit entry points and
    the API workbench. The derived analysis version is recovered from the
    binary-import Job's ``binary-analysis-result`` output via its
    ``parent_version_id``; the sorted result fixes the traversal order so the
    workbench and the auditor cannot drift onto different version sets.
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
