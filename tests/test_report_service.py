from __future__ import annotations

import json

from suscheck.core.finding import ReportFormat
from suscheck.services.report_service import export_report, render_report_content
from suscheck.services.summary_service import build_scan_summary


def _summary():
    return build_scan_summary(
        target="requests",
        artifact_type="package",
        findings=[],
        pri_score=16,
        modules_ran=["supply_chain"],
        modules_skipped=["code"],
        coverage_complete=False,
        coverage_notes=["Modules skipped: code"],
    )


def test_render_report_content_json_contains_contract_fields() -> None:
    payload = render_report_content(_summary(), ReportFormat.JSON)
    data = json.loads(payload)

    assert data["coverage_complete"] is False
    assert data["coverage_notes"] == ["Modules skipped: code"]


def test_render_report_content_json_includes_policy_fields() -> None:
    summary = _summary()
    summary.policy_action = "warn"
    summary.policy_trace = ["coverage: allow", "severity: warn (1 medium finding(s))", "pri: warn (16/100)"]

    payload = render_report_content(summary, ReportFormat.JSON)
    data = json.loads(payload)

    assert data["policy_action"] == "warn"
    assert data["policy_trace"] == summary.policy_trace


def test_render_report_content_json_includes_suppression_fields() -> None:
    summary = _summary()
    summary.suppression_trace = ["suppression: active scope for alice matched 1 finding(s)"]

    payload = render_report_content(summary, ReportFormat.JSON)
    data = json.loads(payload)

    assert data["suppression_trace"] == summary.suppression_trace


def test_render_report_content_json_includes_explainability_fields() -> None:
    summary = _summary()
    summary.explainability_trace = ["Verdict: CAUTION at PRI 16/100", "PRI band: caution (16-40)"]

    payload = render_report_content(summary, ReportFormat.JSON)
    data = json.loads(payload)

    assert data["explainability_trace"] == summary.explainability_trace


def test_render_report_content_json_includes_performance_fields() -> None:
    summary = _summary()
    summary.performance_trace = ["performance: within guardrail (4.00s <= 15.00s for fast)"]

    payload = render_report_content(summary, ReportFormat.JSON)
    data = json.loads(payload)

    assert data["performance_trace"] == summary.performance_trace


def test_render_report_content_json_includes_trend_fields() -> None:
    summary = _summary()
    summary.trend_trace = ["trend: no previous scan snapshot for this target"]

    payload = render_report_content(summary, ReportFormat.JSON)
    data = json.loads(payload)

    assert data["trend_trace"] == summary.trend_trace


def test_render_report_content_json_includes_optional_scanner_trace() -> None:
    summary = _summary()
    summary.optional_scanner_trace = ["optional-scanners: enabled=none (all disabled-by-default)"]

    payload = render_report_content(summary, ReportFormat.JSON)
    data = json.loads(payload)

    assert data["optional_scanner_trace"] == summary.optional_scanner_trace


def test_render_report_content_json_includes_schema_version() -> None:
    summary = _summary()
    summary.schema_version = "1.0"

    payload = render_report_content(summary, ReportFormat.JSON)
    data = json.loads(payload)

    assert data["schema_version"] == "1.0"


def test_export_report_writes_output_file(tmp_path) -> None:
    summary = _summary()
    out_file = tmp_path / "report.json"

    written = export_report(
        summary=summary,
        target="requests",
        report_format=ReportFormat.JSON,
        output=out_file,
        report_dir=None,
        default_report_dir=None,
        use_timestamp=False,
    )

    assert written == out_file
    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["target"] == "requests"
