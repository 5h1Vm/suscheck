"""Policy decisions extracted from CLI command handlers."""

from __future__ import annotations

from dataclasses import dataclass

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


@dataclass(frozen=True)
class WrapperPolicyDecision:
    """Normalized wrapper command policy decision for install/clone/connect."""

    block_partial_coverage: bool
    block_on_pri_threshold: bool
    warn_forced_override: bool


@dataclass(frozen=True)
class PolicyGateDecision:
    """Deterministic policy-as-code outcome for a completed scan."""

    action: str
    trace: list[str]


def evaluate_scan_policy(summary: ScanSummary) -> PolicyGateDecision:
    """Evaluate a deterministic allow/warn/block policy trace from scan summary data.

    The decision is intentionally descriptive and does not alter PRI scoring.
    """
    trace: list[str] = []

    if not summary.coverage_complete:
        trace.append("coverage: block (scan coverage incomplete)")
    else:
        trace.append("coverage: allow (scan coverage complete)")

    critical_count = summary.critical_count
    high_count = summary.high_count
    medium_count = summary.medium_count
    pri_score = summary.pri_score

    if critical_count > 0:
        trace.append(f"severity: block ({critical_count} critical finding(s))")
    elif high_count > 0:
        trace.append(f"severity: hold ({high_count} high finding(s))")
    elif medium_count > 0:
        trace.append(f"severity: warn ({medium_count} medium finding(s))")
    else:
        trace.append("severity: allow (no medium/high/critical findings)")

    if pri_score >= 71:
        trace.append(f"pri: block ({pri_score}/100)")
    elif pri_score >= 41:
        trace.append(f"pri: hold ({pri_score}/100)")
    elif pri_score >= 16:
        trace.append(f"pri: warn ({pri_score}/100)")
    else:
        trace.append(f"pri: allow ({pri_score}/100)")

    action = "allow"
    if any(item.startswith("coverage: block") for item in trace) or any(item.startswith("severity: block") for item in trace) or any(item.startswith("pri: block") for item in trace):
        action = "block"
    elif any(item.startswith("severity: hold") for item in trace) or any(item.startswith("pri: hold") for item in trace):
        action = "hold"
    elif any(item.startswith("severity: warn") for item in trace) or any(item.startswith("pri: warn") for item in trace):
        action = "warn"

    return PolicyGateDecision(action=action, trace=trace)


def evaluate_wrapper_policy(
    summary: ScanSummary,
    *,
    force: bool,
    allow_pri_max: int,
) -> WrapperPolicyDecision:
    """Evaluate shared policy outcomes for wrappers with command-specific PRI threshold."""
    block_partial = should_block_on_partial_coverage(summary, force)
    pri_above_threshold = summary.pri_score > allow_pri_max
    return WrapperPolicyDecision(
        block_partial_coverage=block_partial,
        block_on_pri_threshold=(pri_above_threshold and not force),
        warn_forced_override=(pri_above_threshold and force),
    )
