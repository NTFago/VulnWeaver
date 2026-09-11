"""Print-first report design shared by HTML previews and WeasyPrint PDF."""

from __future__ import annotations

import re
from collections.abc import Sequence
from html import escape

from vulnweaver_contracts import Evidence, Finding, Poc

from vulnweaver_reporting.chinese import LABEL_CONFIDENCE, LABEL_LOCATION, LABEL_STATUS
from vulnweaver_reporting.content import (
    Block,
    BulletList,
    CodeBlock,
    DataTable,
    KeyValueTable,
    Marker,
    Paragraph,
    ReportModel,
    Section,
    build_report_model,
)
from vulnweaver_reporting.context import ReportContext
from vulnweaver_reporting.styles import REPORT_CSS


def build_html(
    findings: Sequence[Finding],
    pocs: Sequence[Poc] = (),
    evidence: dict[str, list[Evidence]] | None = None,
    context: ReportContext | None = None,
) -> str:
    return render_html(build_report_model(findings, pocs, evidence, context))


def render_html(model: ReportModel) -> str:
    cards = "".join(
        f'<div class="metric"><strong>{value}</strong><span>{escape(label)}</span></div>'
        for label, value in model.metrics
    )
    body = "".join(_render_section(section) for section in model.sections)
    return (
        '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">'
        f"<title>{escape(model.title)}</title><style>{REPORT_CSS}</style></head>"
        '<body><main class="document">'
        '<div class="brand"><span class="brand-mark"></span>VULNWEAVER · 漏洞织鉴</div>'
        '<header class="hero"><p class="eyebrow">SECURITY ASSESSMENT / 证据驱动的安全分析</p>'
        "<h1>软件安全审计报告</h1>"
        f'<div class="hero-meta">任务编号：{escape(model.task_id)}<br>'
        f"生成时间：{escape(model.generated_at)} · 中文专业版</div></header>"
        f'<div class="metrics">{cards}</div>{body}'
        '<footer class="document-end">VulnWeaver · 结论限于报告所列样本与证据。'
        "推测、待确认事项与已验证结果分别标注；原始工件保持不可变。</footer>"
        "</main></body></html>"
    )


def _render_section(section: Section) -> str:
    inner = "".join(
        _render_section(block)
        if isinstance(block, Section)
        else _finding_facts(block)
        if isinstance(block, KeyValueTable) and section.kind.startswith("finding ")
        else _render_block(block)
        for block in section.blocks
    )
    heading = f"<h{section.level}>{escape(section.title)}</h{section.level}>"
    if section.kind.startswith("finding "):
        match = re.match(r"3\.(\d+)【(.+?) · (.+?)】(.*)（(CWE-[\d]+)）$", section.title)
        if match:
            number, severity, category, original, cwe = match.groups()
            title = original if re.search(r"[\u4e00-\u9fff]", original) else f"{category}风险审查"
            heading = (
                '<header class="finding-head">'
                f'<div class="finding-number">发现 {int(number):02d} / {escape(cwe)}</div>'
                f'<div class="finding-title"><h3>{escape(title)}</h3>'
                f'<span class="severity">{escape(severity)}</span></div>'
                f'<p class="original-title">原始发现：{escape(original)}</p></header>'
            )
    reference = (
        f'<a class="cross-reference" href="#{escape(section.reference, quote=True)}">'
        "查看完整证据与工件来源 →</a>"
        if section.reference
        else ""
    )
    anchor = f' id="{escape(section.anchor, quote=True)}"' if section.anchor else ""
    return (
        f'<section class="{escape(section.kind, quote=True)}"{anchor}>'
        f"{heading}{inner}{reference}</section>"
    )


def _finding_facts(table: KeyValueTable) -> str:
    facts = "".join(
        f'<div class="fact"><dt>{escape(key)}</dt><dd>{escape(value)}</dd></div>'
        for key, value in table.rows
        if key in {LABEL_CONFIDENCE, LABEL_STATUS, LABEL_LOCATION}
    )
    return f'<dl class="finding-facts">{facts}</dl>'


def _render_block(block: Block) -> str:
    if isinstance(block, KeyValueTable):
        rows = "".join(f"<tr><th>{escape(k)}</th><td>{escape(v)}</td></tr>" for k, v in block.rows)
        return f'<table class="kv"><tbody>{rows}</tbody></table>'
    if isinstance(block, DataTable):
        head = "".join(f"<th>{escape(header)}</th>" for header in block.headers)
        rows = "".join(
            "<tr>" + "".join(f"<td>{escape(cell)}</td>" for cell in row) + "</tr>"
            for row in block.rows
        )
        return f"<table><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table>"
    if isinstance(block, BulletList):
        return "<ul>" + "".join(f"<li>{escape(item)}</li>" for item in block.items) + "</ul>"
    if isinstance(block, Paragraph):
        return f"<p>{escape(block.text)}</p>"
    if isinstance(block, Marker):
        css = "speculative" if block.text.startswith("【") else "note"
        return f'<p class="{css}">{escape(block.text)}</p>'
    if isinstance(block, CodeBlock):
        excerpt = block.excerpt
        lines = "".join(
            f'<div class="code-line"><span class="line-number">{number}</span>'
            f"{escape(line) or ' '}</div>"
            for number, line in enumerate(excerpt["text"].splitlines(), excerpt["first_line"])
        )
        suffix = " · 摘录已截断" if excerpt["truncated"] else ""
        return (
            f'<div class="code-block"><div class="code-caption">{escape(excerpt["label"])}</div>'
            f'{lines}<p class="source-note">来源：{escape(excerpt["source"])}{suffix}</p></div>'
        )
    raise TypeError(f"unsupported report block: {type(block).__name__}")
