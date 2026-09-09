"""Structured report serializers."""

from vulnweaver_reporting.artifacts import register_report
from vulnweaver_reporting.html import build_html
from vulnweaver_reporting.markdown import build_markdown
from vulnweaver_reporting.pdf import render_pdf
from vulnweaver_reporting.sarif import build_sarif, validate_sarif
from vulnweaver_reporting.scheduler import ReportJobScheduler

__all__ = [
    "build_html",
    "build_markdown",
    "build_sarif",
    "register_report",
    "render_pdf",
    "ReportJobScheduler",
    "validate_sarif",
]
