from __future__ import annotations

from suscheck.core.finding import Finding, FindingType, Severity
from suscheck.core.risk_aggregator import RiskAggregator


def _finding(*, module: str, fid: str, ftype: FindingType, value: str, severity: Severity = Severity.MEDIUM) -> Finding:
    return Finding(
        module=module,
        finding_id=fid,
        title=f"{module}:{fid}",
        description="test",
        severity=severity,
        finding_type=ftype,
        confidence=1.0,
        file_path="sample.py",
        line_number=10,
        evidence={"value": value},
    )


def test_pri_deduplicates_repeated_findings_before_scoring() -> None:
    agg = RiskAggregator("CODE")
    repeated_a = _finding(module="code", fid="DUP-1", ftype=FindingType.SUSPICIOUS_BEHAVIOR, value="ioc-a")
    repeated_b = _finding(module="code", fid="DUP-2", ftype=FindingType.SUSPICIOUS_BEHAVIOR, value="ioc-a")

    score = agg.calculate([repeated_a, repeated_b])

    assert score.score == 8
    assert any("deduplicated" in line for line in score.breakdown)


def test_pri_reports_multi_module_indicator_correlation_prep() -> None:
    agg = RiskAggregator("CODE")
    net = _finding(module="code_scanner.network", fid="NET-1", ftype=FindingType.NETWORK_INDICATOR, value="evil.com")
    exfil = _finding(module="repo", fid="EXF-1", ftype=FindingType.DATA_EXFILTRATION, value="evil.com")

    score = agg.calculate([net, exfil])

    assert any("correlated" in line and "multi-module" in line for line in score.breakdown)
