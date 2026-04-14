"""Report export helpers extracted from CLI orchestration."""

from __future__ import annotations

import json
from dataclasses import asdict
from enum import Enum
from pathlib import Path

from suscheck.core.finding import ReportFormat, ScanSummary
from suscheck.core.reporter import ReportGenerator


def _enum_converter(obj):
    if isinstance(obj, Enum):
        return obj.value
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def render_report_content(summary: ScanSummary, report_format: ReportFormat) -> str:
    """Render summary to requested report format content."""
    if report_format == ReportFormat.JSON:
        return json.dumps(asdict(summary), default=_enum_converter, indent=2)
    if report_format == ReportFormat.MARKDOWN:
        return ReportGenerator.generate_markdown(summary)
    if report_format == ReportFormat.HTML:
        return ReportGenerator.generate_html(summary)
    return ""


def resolve_report_path(
    target: str,
    report_format: ReportFormat,
    output: Path | None,
    report_dir: Path | None,
    default_report_dir: str | None,
    use_timestamp: bool,
) -> Path | None:
    """Resolve explicit or default report path for export."""
    if output:
        return output
    if report_format == ReportFormat.TERMINAL:
        return None
    return ReportGenerator.get_default_path(
        target,
        report_format,
        report_dir or default_report_dir,
        timestamped=use_timestamp,
    )


def export_report(
    summary: ScanSummary,
    target: str,
    report_format: ReportFormat,
    output: Path | None,
    report_dir: Path | None,
    default_report_dir: str | None,
    use_timestamp: bool,
) -> Path | None:
    """Export report and return the output path, if written."""
    if report_format == ReportFormat.TERMINAL:
        return None

    content = render_report_content(summary, report_format)
    report_path = resolve_report_path(
        target=target,
        report_format=report_format,
        output=output,
        report_dir=report_dir,
        default_report_dir=default_report_dir,
        use_timestamp=use_timestamp,
    )

    if report_path:
        report_path.write_text(content, encoding="utf-8")
        return report_path

    print(content)
    return None
