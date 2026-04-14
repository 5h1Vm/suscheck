"""Policy decisions extracted from CLI command handlers."""

from __future__ import annotations

from suscheck.core.finding import Finding, ScanSummary, Verdict
from suscheck.core.risk_aggregator import PRIScore


def apply_partial_scan_safety_floor(pri_result: PRIScore, findings: list[Finding]) -> None:
    """Enforce minimum caution score when pipeline is partial."""
    partial_pipeline = any(
        finding.finding_id.startswith("PIPELINE-") and finding.needs_human_review
        for finding in findings
    )
    if partial_pipeline and pri_result.score <= 15:
        pri_result.score = 16
        pri_result.verdict = Verdict.CAUTION
        pri_result.breakdown.append(
            "  [yellow]⚠ Partial Scan Safety Floor[/yellow] -> raised minimum score to [bold]16/100[/bold]"
        )


def should_block_on_partial_coverage(summary: ScanSummary, force: bool) -> bool:
    """Shared wrapper decision: partial coverage requires explicit override."""
    return (not summary.coverage_complete) and (not force)
