"""Tests for AI triage (Increment 13)."""

from unittest.mock import MagicMock, patch

from suscheck.ai.json_extract import parse_json_response
from suscheck.ai.triage_engine import apply_triage_response, run_ai_triage
from suscheck.core.finding import Finding, FindingType, Severity


def test_parse_json_response_strips_fence():
    raw = '```json\n{"a": 1}\n```'
    assert parse_json_response(raw) == {"a": 1}


def test_apply_triage_response_updates_findings():
    f = Finding(
        module="t",
        finding_id="F-1",
        title="t",
        description="d",
        severity=Severity.HIGH,
        finding_type=FindingType.SECRET,
        confidence=0.9,
    )
    data = {
        "pri_adjustment": -5,
        "findings": [
            {
                "finding_id": "F-1",
                "explanation": "Looks like a placeholder.",
                "likely_false_positive": True,
                "confidence": 0.85,
            }
        ],
    }
    adj = apply_triage_response([f], data)
    assert adj == -5.0
    assert f.ai_explanation == "Looks like a placeholder."
    assert f.ai_false_positive is True
    assert f.ai_confidence == 0.85


def test_apply_triage_clamps_pri():
    f = Finding(
        module="t",
        finding_id="F-1",
        title="t",
        description="d",
        severity=Severity.LOW,
        finding_type=FindingType.REVIEW_NEEDED,
        confidence=1.0,
    )
    adj = apply_triage_response([f], {"pri_adjustment": 99, "findings": []})
    assert adj == 15.0


@patch("suscheck.ai.triage_engine.create_ai_provider")
def test_run_ai_triage_skips_unconfigured(mock_factory):
    mock_factory.return_value = MagicMock(is_configured=lambda: False, name="none")
    f = Finding(
        module="t",
        finding_id="x",
        title="t",
        description="d",
        severity=Severity.INFO,
        finding_type=FindingType.REVIEW_NEEDED,
        confidence=1.0,
    )
    res = run_ai_triage([f], target="p", artifact_type="code")
    assert res.ran is False
    assert res.pri_adjustment == 0.0


@patch("suscheck.ai.triage_engine.create_ai_provider")
def test_run_ai_triage_success(mock_factory):
    prov = MagicMock()
    prov.name = "openai"
    prov.is_configured.return_value = True
    prov.complete_triage_json.return_value = {
        "pri_adjustment": 2.0,
        "findings": [
            {
                "finding_id": "x",
                "explanation": "Test explanation",
                "likely_false_positive": False,
                "confidence": 0.7,
            }
        ],
    }
    mock_factory.return_value = prov
    f = Finding(
        module="t",
        finding_id="x",
        title="t",
        description="d",
        severity=Severity.HIGH,
        finding_type=FindingType.SECRET,
        confidence=0.5,
    )
    res = run_ai_triage([f], target="p", artifact_type="code")
    assert res.ran is True
    assert res.pri_adjustment == 2.0
    assert f.ai_explanation == "Test explanation"
