"""Tests for the Platform Risk Index (PRI) Scoring Engine."""

import pytest

from suscheck.core.finding import Finding, FindingType, Severity, Verdict
from suscheck.core.risk_aggregator import RiskAggregator, PRIScore

def test_base_scoring():
    # 25 * 1.0 + 15 * 0.5 + 3 * 1.0 = 25 + 7.5 + 3 = 35.5 -> int -> 35
    findings = [
        Finding(finding_id="1", title="Critical", description="desc", severity=Severity.CRITICAL, confidence=1.0, module="test", finding_type=FindingType.SUSPICIOUS_BEHAVIOR),
        Finding(finding_id="2", title="High low conf", description="desc", severity=Severity.HIGH, confidence=0.5, module="test", finding_type=FindingType.SECRET_EXPOSURE),
        Finding(finding_id="3", title="Low", description="desc", severity=Severity.LOW, confidence=1.0, module="test", finding_type=FindingType.REVIEW_NEEDED),
    ]
    
    agg = RiskAggregator("CODE")
    pri = agg.calculate(findings)
    assert pri.score == 35
    assert pri.verdict == Verdict.CAUTION

def test_context_multiplier_script():
    # 25 -> 37.5 -> 37
    findings = [
        Finding(finding_id="1", title="Critical", description="desc", severity=Severity.CRITICAL, confidence=1.0, module="test", finding_type=FindingType.SECRET_EXPOSURE),
    ]
    
    agg = RiskAggregator("BASH SCRIPT")  # Should trigger 1.5x multiplier
    pri = agg.calculate(findings)
    assert pri.score == 37  # int(25 * 1.5) -> int(37.5) = 37

def test_context_multiplier_package():
    # 25 -> 35
    findings = [
        Finding(finding_id="1", title="Critical", description="desc", severity=Severity.CRITICAL, confidence=1.0, module="test", finding_type=FindingType.SECRET_EXPOSURE),
    ]
    
    agg = RiskAggregator("PYTHON PACKAGE")  # Should trigger 1.4x multiplier
    pri = agg.calculate(findings)
    assert pri.score == 35  # int(25 * 1.4) = 35

def test_correlation_evasion_attempt():
    # Obfuscation (File Mismatch) + Execution
    findings = [
        Finding(finding_id="1", title="Execution", description="desc", severity=Severity.HIGH, confidence=1.0, module="test", finding_type=FindingType.SUSPICIOUS_BEHAVIOR),
        Finding(finding_id="2", title="Obfuscation", description="desc", severity=Severity.LOW, confidence=1.0, module="test", finding_type=FindingType.FILE_MISMATCH),
    ]
    # BASE: 15 (High) + 3 (Low) = 18.
    # CORRELATION: +15
    # TOTAL: 33
    agg = RiskAggregator("CODE")
    pri = agg.calculate(findings)
    assert pri.score == 33
    assert any("Evasion Attempt" in item for item in pri.breakdown)

def test_correlation_staged_attack():
    # Network + Execution
    findings = [
        Finding(finding_id="1", title="Execution", description="desc", severity=Severity.HIGH, confidence=1.0, module="test", finding_type=FindingType.SUSPICIOUS_BEHAVIOR),
        Finding(finding_id="2", title="Network", description="desc", severity=Severity.MEDIUM, confidence=1.0, module="test", finding_type=FindingType.NETWORK_INDICATOR),
    ]
    # BASE: 15 + 8 = 23.
    # CORRELATION: +30
    # TOTAL: 53
    agg = RiskAggregator("CODE")
    pri = agg.calculate(findings)
    assert pri.score == 53
    assert any("Staged Attack" in item for item in pri.breakdown)

def test_virustotal_adjustments():
    findings = [
        Finding(finding_id="1", title="Info", description="desc", severity=Severity.INFO, confidence=1.0, module="test", finding_type=FindingType.REVIEW_NEEDED),
    ]
    
    agg = RiskAggregator("CODE")
    
    # Clean: base 1 + (-5) = -4 -> 0
    clean_vt = {"status": "found", "data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0}}}}
    pri = agg.calculate(findings, clean_vt)
    assert pri.score == 0
    
    # Malicious (5 engines): base 1 + 25 = 26
    mal_vt = {"status": "found", "data": {"attributes": {"last_analysis_stats": {"malicious": 5, "suspicious": 0}}}}
    pri2 = agg.calculate(findings, mal_vt)
    assert pri2.score == 26
    
    # Critical (20 engines): base 1 + 40 = 41
    crit_vt = {"status": "found", "data": {"attributes": {"last_analysis_stats": {"malicious": 20, "suspicious": 0}}}}
    pri3 = agg.calculate(findings, crit_vt)
    assert pri3.score == 41

def test_max_score_clamp():
    # Very high score -> clamp to 100
    findings = [
        Finding(finding_id="1", title="Execution", description="desc", severity=Severity.CRITICAL, confidence=1.0, module="test", finding_type=FindingType.SUSPICIOUS_BEHAVIOR) for _ in range(10)
    ]
    # 250 base score
    agg = RiskAggregator("CODE")
    pri = agg.calculate(findings)
    assert pri.score == 100
    assert pri.verdict == Verdict.ABORT
    assert "raw:" in pri.breakdown[-1]

def test_neutral_findings_ignored():
    findings = [
        Finding(finding_id="VT-CLEAN-001", title="Neutral", description="desc", severity=Severity.CRITICAL, confidence=1.0, module="test", finding_type=FindingType.SUSPICIOUS_BEHAVIOR),
    ]
    agg = RiskAggregator("CODE")
    pri = agg.calculate(findings)
    assert pri.score == 0


def test_ai_pri_adjustment_clamped():
    findings = [
        Finding(
            finding_id="1",
            title="Low",
            description="d",
            severity=Severity.LOW,
            confidence=1.0,
            module="test",
            finding_type=FindingType.REVIEW_NEEDED,
        ),
    ]
    agg = RiskAggregator("CODE")
    pri = agg.calculate(findings, ai_pri_delta=10.0)
    assert pri.score == 13  # 3 + 10
    pri2 = agg.calculate(findings, ai_pri_delta=100.0)
    assert pri2.score == 18  # 3 + 15 clamp
    assert any("AI Triage Adjustment" in b for b in pri2.breakdown)


def test_trust_score_influences_pri():
    """Low trust should raise PRI, high trust should lower it."""
    findings = [
        Finding(
            finding_id="1",
            title="Medium",
            description="d",
            severity=Severity.MEDIUM,
            confidence=1.0,
            module="test",
            finding_type=FindingType.REVIEW_NEEDED,
        ),
    ]

    agg = RiskAggregator("CODE")
    base = agg.calculate(findings).score

    low_trust = agg.calculate(findings, trust_score=2.0)
    high_trust = agg.calculate(findings, trust_score=9.0)

    assert low_trust.score > base
    assert high_trust.score < base
    assert any("Trust Score" in b for b in low_trust.breakdown)
