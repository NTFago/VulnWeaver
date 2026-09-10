"""Bounded Markdown report rendering driven by the shared Chinese report model."""

from __future__ import annotations

from collections.abc import Sequence

from vulnweaver_contracts import Evidence, Finding, Poc

from vulnweaver_reporting.content import (
    Block,
    BulletList,
    DataTable,
    KeyValueTable,
    Marker,
    Paragraph,
    ReportModel,
    Section,
    build_report_model,
)
from vulnweaver_reporting.context import ReportContext


def build_markdown(
    findings: Sequence[Finding],
    pocs: Sequence[Poc] = (),
    evidence: dict[str, list[Evidence]] | None = None,
    context: ReportContext | None = None,
) -> str:
    """Render the Chinese audit report while keeping raw evidence out of the document."""
    return render_markdown(
        build_report_model(findings, pocs, evidence, context),
    )


def render_markdown(model: ReportModel) -> str:
    """Render a report model as bounded Markdown text."""
    lines: list[str] = [f"# {model.title}", ""]
    for section in model.sections:
        _render_section(section, lines)
    return "\n".join(lines)


def _render_section(section: Section, lines: list[str]) -> None:
    lines += [f"{'#' * section.level} {section.title}", ""]
    for block in section.blocks:
        if isinstance(block, Section):
            _render_section(block, lines)
        else:
            _render_block(block, lines)


def _render_block(block: Block, lines: list[str]) -> None:
    if isinstance(block, KeyValueTable):
        lines += [
            "| " + " | ".join(_cell(header) for header in block.headers) + " |",
            "| " + " | ".join("---" for _ in block.headers) + " |",
        ]
        lines += [f"| {_cell(label)} | {_cell(value)} |" for label, value in block.rows]
    elif isinstance(block, DataTable):
        lines += [
            "| " + " | ".join(_cell(header) for header in block.headers) + " |",
            "| " + " | ".join("---" for _ in block.headers) + " |",
        ]
        lines += [
            "| " + " | ".join(_cell(cell) for cell in row) + " |" for row in block.rows
        ]
    elif isinstance(block, BulletList):
        lines += [f"- {_line(item)}" for item in block.items]
    elif isinstance(block, Paragraph):
        lines += [_line(block.text)]
    elif isinstance(block, Marker):
        lines += [f"> {block.text}"]
    else:  # pragma: no cover - the union above is exhaustive
        raise TypeError(f"unsupported report block: {type(block).__name__}")
    lines.append("")


def _cell(value: str) -> str:
    """Keep a value inside one Markdown table cell."""
    return _line(value).replace("|", "\\|")


def _line(value: str) -> str:
    """Collapse line breaks so a value stays on one report line."""
    return value.replace("\r", " ").replace("\n", " ").strip()
