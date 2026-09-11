"""Optional report context assembled from persisted task-level metadata.

The renderers stay pure functions over contracts; this TypedDict carries the
task-level facts (sample identity, review history) that only the executor can
read from the database. Every key is optional so existing callers and tests can
render a complete report without a context.
"""

from __future__ import annotations

from typing import TypedDict

from vulnweaver_contracts import Review


class SampleSummary(TypedDict):
    """One tested input artifact with its upload-time identity."""

    name: str
    digest: str
    kind: str


class CodeExcerpt(TypedDict):
    """Bounded, attributable source or decompiler output; never model-invented code."""

    text: str
    label: str
    source: str
    first_line: int
    truncated: bool


class ReportContext(TypedDict, total=False):
    """Task metadata consumed by the Markdown and HTML report renderers."""

    task_id: str
    task_created_at: str
    task_updated_at: str
    task_result: str | None
    failure_code: str | None
    failure_kind: str | None
    failure_message: str | None
    produced_by: str
    samples: list[SampleSummary]
    reviews: dict[str, list[Review]]
    excerpts: dict[str, CodeExcerpt]
    excerpt_errors: dict[str, str]
    evidence_relations: dict[str, dict[str, str]]
    job_failures: list[str]
    task_status: str
    generated_at: str


def empty_context() -> ReportContext:
    """Return a context for renderers called without persisted metadata."""
    return ReportContext()
