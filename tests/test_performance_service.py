from __future__ import annotations

from types import SimpleNamespace

from suscheck.core.finding import ScanSummary, Verdict
from suscheck.services.performance_service import evaluate_performance_guardrails


def _summary(scan_duration: float) -> ScanSummary:
    return ScanSummary(
        target="sample",
        artifact_type="code",
        pri_score=10,
        verdict=Verdict.CLEAR,
        findings=[],
        total_findings=0,
        critical_count=0,
        high_count=0,
        medium_count=0,
        low_count=0,
        info_count=0,
        review_count=0,
        scan_duration=scan_duration,
        modules_ran=["tier0"],
    )


def test_evaluate_performance_guardrails_allows_fast_scan() -> None:
    result = evaluate_performance_guardrails(profile="fast", summary=_summary(4.0))

    assert result.findings == []
    assert any("within guardrail" in step for step in result.trace)


def test_evaluate_performance_guardrails_flags_regression() -> None:
    result = evaluate_performance_guardrails(profile="fast", summary=_summary(20.0))

    assert any(finding.finding_id == "PERF-REGRESSION" for finding in result.findings)
    assert any("regression" in step for step in result.trace)