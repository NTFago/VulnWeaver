"""PDF rendering backed by the Dev Container's pinned WeasyPrint runtime."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from vulnweaver_contracts import Evidence, Finding, Poc

from vulnweaver_reporting.context import ReportContext
from vulnweaver_reporting.html import build_html


def render_pdf(
    findings: list[Finding],
    output: str | Path,
    *,
    pocs: Sequence[Poc] = (),
    evidence: dict[str, list[Evidence]] | None = None,
    context: ReportContext | None = None,
) -> Path:
    """Render a bounded report to a caller-owned output path."""
    try:
        from weasyprint import HTML  # pyright: ignore[reportMissingTypeStubs]
    except ImportError as error:
        raise RuntimeError(
            "PDF rendering requires the reporting Dev Container dependency"
        ) from error
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    HTML(  # pyright: ignore[reportUnknownMemberType]
        string=build_html(findings, pocs, evidence, context),
        url_fetcher=_deny_external_resource,
    ).write_pdf(destination)
    return destination


def _deny_external_resource(url: str, *args: object, **kwargs: object) -> dict[str, object]:
    """Reports use installed fonts and inline CSS; no file or network fetching."""
    raise ValueError("report resources must be embedded by the renderer")
