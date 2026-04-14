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
