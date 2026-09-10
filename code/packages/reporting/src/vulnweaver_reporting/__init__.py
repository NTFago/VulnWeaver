"""Structured report serializers."""

from vulnweaver_reporting.artifacts import register_report
from vulnweaver_reporting.content import build_report_model
from vulnweaver_reporting.executor import ReportJobExecutor
from vulnweaver_reporting.html import build_html, render_html
from vulnweaver_reporting.markdown import build_markdown, render_markdown
from vulnweaver_reporting.pdf import render_pdf
from vulnweaver_reporting.sarif import build_sarif, validate_sarif
from vulnweaver_reporting.scheduler import ReportJobScheduler

__all__ = [
    "ReportJobExecutor",
    "ReportJobScheduler",
    "build_html",
    "build_markdown",
    "build_report_model",
    "build_sarif",
    "register_report",
    "render_html",
    "render_markdown",
    "render_pdf",
    "validate_sarif",
]
