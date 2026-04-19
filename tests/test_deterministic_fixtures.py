from __future__ import annotations

import json
from pathlib import Path

import pytest

from suscheck.core.finding import Finding, FindingType, Severity
from suscheck.core.risk_aggregator import RiskAggregator
from suscheck.services.summary_service import derive_coverage_contract


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "golden"


def _to_finding(item: dict) -> Finding:
    return Finding(
        module=item["module"],
        finding_id=item["finding_id"],
        title=item["title"],
        description=item["description"],
        severity=Severity(item["severity"]),
        finding_type=FindingType(item["finding_type"]),
        confidence=float(item.get("confidence", 1.0)),
        evidence=item.get("evidence", {}),
        needs_human_review=bool(item.get("needs_human_review", False)),
    )


@pytest.mark.parametrize("fixture_name", ["safe", "suspicious", "malicious"])
def test_golden_fixture_pri_band_and_coverage_contract(fixture_name: str) -> None:
    data = json.loads((FIXTURE_DIR / f"{fixture_name}.json").read_text(encoding="utf-8"))
    findings = [_to_finding(item) for item in data["findings"]]

    pri = RiskAggregator(data["artifact_type"]).calculate(findings)
    coverage_complete, _notes = derive_coverage_contract(findings, modules_skipped=data.get("modules_skipped", []))

    expected = data["expected"]
    assert pri.verdict.value == expected["verdict"]
    assert expected["score_min"] <= pri.score <= expected["score_max"]
    assert coverage_complete is expected["coverage_complete"]
