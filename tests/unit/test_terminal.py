"""Tests for the rich terminal output renderer."""

import pytest
from unittest.mock import MagicMock, patch
from suscheck.output.terminal import (
    render_scan_header, render_verdict, render_findings, 
    render_code_snippet, render_vt_result, render_scan_footer
)
from suscheck.core.finding import Finding, Severity, FindingType, ScanSummary, Verdict

@pytest.fixture
def mock_console():
    with patch("suscheck.output.terminal.console") as mock:
        yield mock

def test_render_scan_header(mock_console):
    render_scan_header("test_target", "code", "1.0.0")
    assert mock_console.print.called

def test_render_verdict(mock_console):
    summary = ScanSummary(
        target="t",
        artifact_type="a",
        findings=[],
        total_findings=0,
        verdict=Verdict.ABORT,
        pri_score=85,
        critical_count=1,
        high_count=2,
        medium_count=0,
        low_count=0,
        info_count=0,
        review_count=0,
        scan_duration=1.5,
        modules_ran=["m1"],
        modules_skipped=[]
    )
    render_verdict(summary)
    assert mock_console.print.called

def test_render_findings_empty(mock_console):
    render_findings([])
    assert mock_console.print.called

def test_render_findings_with_data(mock_console):
    findings = [
        Finding(
            module="m1", 
            finding_id="id1", 
            title="T1", 
            description="D1", 
            severity=Severity.CRITICAL, 
            finding_type=FindingType.DANGEROUS_FUNCTION,
            confidence=1.0,
            ai_explanation="AI explains it"
        ),
        Finding(
            module="m2", 
            finding_id="id2", 
            title="T2", 
            description="D2", 
            severity=Severity.LOW, 
            finding_type=FindingType.REVIEW_NEEDED,
            confidence=0.1
        )
    ]
    render_findings(findings)
    assert mock_console.print.called

def test_render_code_snippet(mock_console):
    finding = Finding(
        module="m", finding_id="i", title="t", description="d", 
        severity=Severity.INFO, finding_type=FindingType.SUSPICIOUS_BEHAVIOR, 
        confidence=1.0, code_snippet="print('hello')", line_number=10
    )
    render_code_snippet(finding)
    assert mock_console.print.called

def test_render_vt_result(mock_console):
    vt_data = {
        "found": True,
        "detection_count": 5,
        "total_engines": 70,
        "detection_names": ["Eng1: Malware"],
        "vt_link": "http://vt.com"
    }
    render_vt_result(vt_data)
    assert mock_console.print.called

def test_render_scan_footer(mock_console):
    summary = ScanSummary(
        target="t",
        artifact_type="a",
        findings=[],
        total_findings=0,
        verdict=Verdict.CLEAR, pri_score=0, critical_count=0, high_count=0,
        medium_count=0, low_count=0, info_count=0, review_count=0,
        scan_duration=2.0, modules_ran=["m1"], modules_skipped=["m2"]
    )
    render_scan_footer(summary)
    assert mock_console.print.called
