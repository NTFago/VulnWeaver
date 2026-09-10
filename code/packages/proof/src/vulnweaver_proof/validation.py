"""Centralized ownership checks for proof/exploit inputs.

Project ownership of a CAS reference only exists in the relational artifact
metadata, so both scheduling and execution must resolve the reference through
the repositories instead of trusting the caller-supplied string.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

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


@dataclass(frozen=True, slots=True)
class GeneratedScriptPolicyResult:
    allowed: bool
    reason_codes: tuple[str, ...]


_FORBIDDEN_SCRIPT_PATTERNS = {
    "persistence": re.compile(
        r"(?i)(crontab|systemctl\s+(?:enable|start)|/etc/rc\.local|authorized_keys)"
    ),
    "lateral_movement": re.compile(r"(?i)(ssh\s+|scp\s+|/etc/hosts|/etc/passwd\b)"),
    "external_network": re.compile(r"(?i)(https?://|curl\s+|wget\s+|socket\.|requests\.)"),
}


def validate_generated_script(
    script: str, *, max_bytes: int = 256 * 1024
) -> GeneratedScriptPolicyResult:
    """Check generated PoC text against the exploit safety red lines."""
    if max_bytes < 1:
        raise ValueError("script size limit must be positive")
    if not isinstance(script, str) or not script.strip():
        return GeneratedScriptPolicyResult(False, ("empty_script",))
    if len(script.encode("utf-8")) > max_bytes:
        return GeneratedScriptPolicyResult(False, ("script_too_large",))
    reasons = tuple(
        code for code, pattern in _FORBIDDEN_SCRIPT_PATTERNS.items() if pattern.search(script)
    )
    return GeneratedScriptPolicyResult(not reasons, reasons)
