"""Self-contained screen and print styles; use fonts from the worker image."""

REPORT_CSS = """
@page {
    size: A4;
    margin: 22mm 18mm 20mm;
    font-family: "Noto Sans CJK SC", sans-serif;
    @top-left {
        content: "VULNWEAVER  /  漏洞织鉴";
        font-size: 8pt;
        color: #526170;
    }
    @top-right {
        content: "软件安全审计报告";
        font-size: 8pt;
        color: #526170;
    }
    @bottom-left {
        content: "证据驱动 · 限于本次授权审计范围";
        font-size: 7pt;
        color: #64748b;
    }
    @bottom-right {
        content: counter(page) " / " counter(pages);
        font-size: 8pt;
        color: #334155;
    }
}
* { box-sizing: border-box; }
body {
    font-family: "Noto Sans CJK SC", "Noto Sans SC", "Microsoft YaHei", sans-serif;
    color: #182739;
    background: white;
    font-size: 10pt;
    line-height: 1.45;
    margin: 0;
}
.brand {
    font-size: 8pt; font-weight: 700; letter-spacing: 2px;
    color: #4d6653; margin-bottom: 15px;
}
.brand-mark {
    display: inline-block; background: #c9f43b;
    width: 11px; height: 11px; margin-right: 8px;
}
.hero { border-top: 4px solid #172b3b; padding-top: 16px; margin-bottom: 20px; }
.eyebrow { font-size: 8pt; color: #64748b; letter-spacing: 2px; margin: 0 0 3px; }
h1 {
    font-size: 27pt; line-height: 1.2; letter-spacing: 1px;
    margin: 0 0 10px; font-weight: 800;
}
.hero-meta { font-size: 8pt; color: #526170; overflow-wrap: anywhere; }
.metrics {
    display: table; table-layout: fixed; width: 100%;
    border: 1px solid #d5dedf; margin: 16px 0 20px;
}
.metric {
    display: table-cell; padding: 13px 14px;
    border-right: 1px solid #d5dedf; background: #f7f9f8;
}
.metric:last-child { border: 0; }
.metric strong { font-size: 25pt; line-height: 1.2; display: block; color: #173c32; }
.metric span { display: block; font-size: 8pt; color: #536575; margin-top: 4px; }
h2, h3, h4 { overflow-wrap: anywhere; break-after: avoid; }
h2 {
    font-size: 13pt; letter-spacing: .3px; margin: 18px 0 10px;
    border-left: 4px solid #8bac26; padding: 5px 10px; background: #f0f4f3;
}
h3 { font-size: 10.5pt; margin: 14px 0 8px; }
h4 { font-size: 9.5pt; color: #34524b; margin: 12px 0 4px; }
p { margin: 5px 0 9px; orphans: 3; widows: 3; overflow-wrap: anywhere; }
table {
    border-collapse: collapse; width: 100%; margin: 7px 0 12px;
    table-layout: fixed; font-size: 8.5pt;
}
th, td {
    border-bottom: 1px solid #e0e6e8; padding: 6px 8px;
    text-align: left; vertical-align: top; overflow-wrap: anywhere;
}
th { background: #f5f7f8; color: #526170; font-weight: 500; }
thead { display: table-header-group; }
.kv th { width: 24%; }
.kv td { width: 76%; }
.summary .kv tr:last-child td { font-weight: 600; color: #234f40; }
.statistics { margin-bottom: 20px; }
.statistics > section { display: inline-block; width: 48%; vertical-align: top; }
.statistics > section + section { margin-left: 3%; }
.statistics td:last-child { font-weight: 700; }
.findings { break-before: page; }
.finding {
    padding: 0 0 12px; margin: 16px 0; border-bottom: 1px solid #cfdadd;
}
.finding-head {
    border-top: 3px solid #193b36; padding-top: 10px;
    break-inside: avoid; break-after: avoid;
}
.finding-number { font-size: 8pt; color: #658078; letter-spacing: 1px; margin-bottom: 5px; }
.finding-title { display: table; table-layout: fixed; width: 100%; }
.finding-title h3 {
    display: table-cell; font-size: 15pt; line-height: 1.4;
    margin: 0; width: 78%; padding-right: 12px;
}
.severity {
    display: table-cell; text-align: right; vertical-align: top;
    font-size: 9pt; font-weight: 700; color: #b45309;
}
.critical .severity { color: #b42332; }
.high .severity { color: #b45309; }
.medium .severity { color: #9a720d; }
.low .severity, .info .severity { color: #245d6b; }
.original-title { font-size: 8.5pt; color: #65737e; margin: 6px 0; overflow-wrap: anywhere; }
.finding-facts {
    margin: 12px 0; background: #f5f7f8; padding: 5px 10px;
    border: 1px solid #e0e6e8;
}
.fact {
    display: inline-block; width: 25%; vertical-align: top;
    padding: 5px 8px; overflow-wrap: anywhere;
}
.fact:last-child { width: 50%; }
.fact dt { font-size: 7.5pt; color: #65737e; }
.fact dd { margin: 2px 0 0; font-size: 8.5pt; }
.finding h4 { margin-top: 8px; }
.finding > section { break-inside: avoid; }
.finding p { margin: 4px 0 6px; }
.finding li { margin-bottom: 2px; }
.call-path li { display: inline; padding: 0; }
.call-path li + li:before { content: " · "; color: #789087; }
.call-path ul { padding-left: 0; }
.cross-reference {
    display: block; font-size: 8pt; color: #37695a;
    text-decoration: none; margin: 4px 0 8px;
}
.note, .speculative {
    padding: 6px 11px; border-left: 3px solid #c79c37; background: #fbf7eb;
    color: #76591b; font-size: 8pt; margin: 6px 0; break-inside: avoid;
}
.speculative { border-color: #cc7968; background: #fcf3ef; color: #874c3e; }
.code-block {
    margin: 12px 0; border: 1px solid #dce3e6;
    border-left: 3px solid #627b73; background: #f6f8fa;
}
.code-caption {
    font-size: 8pt; font-weight: 700; background: #edf2f3;
    padding: 7px 10px; break-after: avoid;
}
.code-line {
    font-family: "DejaVu Sans Mono", "Noto Sans CJK SC", monospace;
    font-size: 8.5pt; line-height: 1.4; white-space: pre-wrap;
    overflow-wrap: anywhere; padding: 0 10px; orphans: 2; widows: 2;
}
.code-line:last-of-type { padding-bottom: 9px; }
.line-number { color: #8a98a4; display: inline-block; width: 34px; user-select: none; }
.source-note {
    font-size: 7pt; color: #6d7b85; padding: 6px 10px;
    margin: 0; border-top: 1px solid #e0e6e8;
}
ul { margin: 5px 0 9px; padding-left: 17px; }
li { padding-left: 2px; margin-bottom: 5px; overflow-wrap: anywhere; }
.appendix { font-size: 8.5pt; margin-top: 24px; }
.appendix h4 { font-family: monospace; font-size: 8pt; overflow-wrap: anywhere; }
.appendix li { color: #526170; }
.document-end {
    margin-top: 22px; border-top: 2px solid #203e36;
    padding-top: 10px; color: #65737e; font-size: 7.5pt;
}
@media screen {
    body { background: #e9eeef; padding: 32px; }
    .document {
        max-width: 850px; margin: auto; background: white;
        padding: 48px 55px; box-shadow: 0 12px 40px #172b3b14;
    }
    .findings, .appendix { margin-top: 35px; }
}
@media screen and (max-width: 650px) {
    body { padding: 0; }
    .document { padding: 24px 18px; }
    .metric { padding: 10px 6px; }
    .metric strong { font-size: 21pt; }
    .statistics > section { width: 100%; }
    .statistics > section + section { margin-left: 0; }
    .fact, .fact:last-child { width: 100%; }
}
"""
