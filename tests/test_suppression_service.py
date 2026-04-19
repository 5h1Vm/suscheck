from __future__ import annotations

from datetime import date

from suscheck.core.finding import Finding, FindingType, Severity
from suscheck.services.suppression_service import SuppressionEntry, evaluate_suppressions


def _finding() -> Finding:
    return Finding(
        module="code",
        finding_id="CODE-1",
        title="Code finding",
        description="test",
        severity=Severity.HIGH,
        finding_type=FindingType.SUSPICIOUS_BEHAVIOR,
        confidence=1.0,
        file_path="sample.py",
        evidence={},
    )


def test_evaluate_suppressions_flags_expired_entries() -> None:
    result = evaluate_suppressions(
        findings=[_finding()],
        suppressions=[
            SuppressionEntry(
                owner="alice",
                reason="temporary waiver",
                expiry="2024-01-01",
                scope={"finding_id": "CODE-1"},
            )
        ],
        today=date(2026, 4, 19),
    )

    assert result.loaded_entries == 1
    assert any(f.finding_id.startswith("SUPPRESSION-EXPIRED-") for f in result.findings)
    assert any("expired" in step for step in result.trace)


def test_evaluate_suppressions_reports_active_match_without_silencing_findings() -> None:
    result = evaluate_suppressions(
        findings=[_finding()],
        suppressions=[
            SuppressionEntry(
                owner="bob",
                reason="accepted risk",
                expiry="2026-12-31",
                scope={"finding_id": "CODE-1", "module": "code"},
            )
        ],
        today=date(2026, 4, 19),
    )

    assert result.findings == []
    assert any("active scope" in step for step in result.trace)