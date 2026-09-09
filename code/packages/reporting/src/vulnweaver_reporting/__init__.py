"""Structured report serializers."""

from vulnweaver_reporting.markdown import build_markdown
from vulnweaver_reporting.sarif import build_sarif

__all__ = ["build_markdown", "build_sarif"]
