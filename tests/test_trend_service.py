from __future__ import annotations

from suscheck.core.finding import Finding, FindingType, Severity, Verdict
from suscheck.core.finding import ScanSummary
from suscheck.services.trend_service import compare_and_record_trend


def _summary(pri_score: int, total_findings: int, coverage_complete: bool = True) -> ScanSummary:
    return ScanSummary(
        target="requests",
        artifact_type="package",
        pri_score=pri_score,
        verdict=Verdict.CLEAR if pri_score <= 15 else Verdict.CAUTION,
        findings=[
            Finding(
                module="code",
                finding_id="CODE-1",
                title="Code finding",
                description="test",
                severity=Severity.LOW,
                finding_type=FindingType.SUSPICIOUS_BEHAVIOR,
                confidence=1.0,
            )
        ] * total_findings,
        total_findings=total_findings,
        critical_count=0,
        high_count=0,
        medium_count=0,
        low_count=0,
        info_count=0,
        review_count=0,
        scan_duration=1.0,
        modules_ran=["tier0"],
        coverage_complete=coverage_complete,
    )


def test_compare_and_record_trend_reports_first_run(tmp_path) -> None:
    store = tmp_path / "trends.json"
    result = compare_and_record_trend(_summary(10, 1), store_path=store)

    assert result.previous_snapshot is None
    assert any("no previous" in step for step in result.trace)
    assert store.exists()


def test_compare_and_record_trend_reports_delta_on_repeat_run(tmp_path) -> None:
    store = tmp_path / "trends.json"
    compare_and_record_trend(_summary(10, 1), store_path=store)
    result = compare_and_record_trend(_summary(18, 3, coverage_complete=False), store_path=store)

    assert result.previous_snapshot is not None
    assert any("previous PRI 10/100 -> 18/100" in step for step in result.trace)
    assert any("previous findings 1 -> 3" in step for step in result.trace)
    assert any("coverage" in step for step in result.trace)
