"""Centralized ownership checks for proof/exploit inputs.

Project ownership of a CAS reference only exists in the relational artifact
metadata, so both scheduling and execution must resolve the reference through
the repositories instead of trusting the caller-supplied string.
"""

from __future__ import annotations

from vulnweaver_persistence import Repositories


class ScriptRefOwnershipError(PermissionError):
    """Raised when a script reference does not belong to the finding's project."""


async def ensure_script_ref_belongs_to_project(
    repositories: Repositories, *, script_ref: str, project_id: str
) -> None:
    version = await repositories.artifacts.find_project_version_by_object_ref(
        script_ref, project_id=project_id
    )
    if version is None:
        raise ScriptRefOwnershipError(
            "script reference does not resolve to an artifact version of the task project"
        )
