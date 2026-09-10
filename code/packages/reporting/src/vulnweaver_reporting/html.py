"""HTML source for deterministic, Chinese-first PDF rendering."""

from __future__ import annotations

from collections.abc import Sequence
from html import escape

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

# Chinese-capable fonts first so WeasyPrint renders CJK text in the container
# that ships fonts-noto-cjk; the remaining entries cover other platforms.
_CSS = """
body{font-family:"Noto Sans CJK SC","Noto Sans SC","Source Han Sans SC",
"WenQuanYi Micro Hei","Microsoft YaHei","PingFang SC",sans-serif;
color:#1e293b;margin:2rem;font-size:13px;line-height:1.6}
h1{font-size:24px;border-bottom:3px solid #334155;padding-bottom:8px}
h2{font-size:19px;border-bottom:2px solid #64748b;padding-bottom:5px;margin-top:28px}
h3{font-size:16px;margin-top:20px}
h4{font-size:14px;margin-top:16px;color:#334155}
table{border-collapse:collapse;width:100%;margin:10px 0}
th,td{border:1px solid #cbd5e1;padding:5px 9px;text-align:left;vertical-align:top}
th{background:#f1f5f9}
article{border:1px solid #e2e8f0;border-radius:8px;padding:4px 14px 10px;
margin:16px 0;page-break-inside:avoid}
.note{background:#fff7ed;border-left:4px solid #f97316;color:#9a3412;
padding:6px 10px;margin:8px 0}
.speculative{background:#fef2f2;border-left:4px solid #dc2626;color:#991b1b;
padding:6px 10px;margin:8px 0}
section{page-break-inside:auto}
""".replace("\n", "")


def build_html(
    findings: Sequence[Finding],
    pocs: Sequence[Poc] = (),
    evidence: dict[str, list[Evidence]] | None = None,
    context: ReportContext | None = None,
) -> str:
    """Build a self-contained, escaped Chinese HTML report suitable for a PDF engine."""
    return render_html(build_report_model(findings, pocs, evidence, context))


def render_html(model: ReportModel) -> str:
    """Render a report model as a self-contained HTML document."""
    body = "".join(_render_section(section) for section in model.sections)
    return (
        "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
        f"<title>{escape(model.title)}</title>"
        f"<style>{_CSS}</style></head>"
        f"<body><h1>{escape(model.title)}</h1>{body}</body></html>"
    )


def _render_section(section: Section) -> str:
    blocks: list[str] = []
    for block in section.blocks:
        if isinstance(block, Section):
            blocks.append(_render_section(block))
        else:
            blocks.append(_render_block(block))
    heading = f"<h{section.level}>{escape(section.title)}</h{section.level}>"
    inner = "".join(blocks)
    if section.level == 3 and section.title[:2] == "3.":
        return f"<article>{heading}{inner}</article>"
    return f"<section>{heading}{inner}</section>"


def _render_block(block: Block) -> str:
    if isinstance(block, KeyValueTable):
        rows = "".join(
            f"<tr><th>{escape(label)}</th><td>{escape(value)}</td></tr>"
            for label, value in block.rows
        )
        return f"<table>{rows}</table>"
    if isinstance(block, DataTable):
        headers = "".join(f"<th>{escape(header)}</th>" for header in block.headers)
        rows = "".join(
            "<tr>" + "".join(f"<td>{escape(cell)}</td>" for cell in row) + "</tr>"
            for row in block.rows
        )
        return f"<table><tr>{headers}</tr>{rows}</table>"
    if isinstance(block, BulletList):
        items = "".join(f"<li>{escape(item)}</li>" for item in block.items)
        return f"<ul>{items}</ul>"
    if isinstance(block, Paragraph):
        return f"<p>{escape(block.text)}</p>"
    if isinstance(block, Marker):
        css_class = "speculative" if block.text.startswith("【") else "note"
        return f"<p class=\"{css_class}\">{escape(block.text)}</p>"
    raise TypeError(f"unsupported report block: {type(block).__name__}")  # pragma: no cover
