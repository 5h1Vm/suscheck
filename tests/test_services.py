from __future__ import annotations

from suscheck.core.finding import Finding, FindingType, Severity, Verdict
from suscheck.core.risk_aggregator import PRIScore
from suscheck.services.policy_service import (
    apply_partial_scan_safety_floor,
    evaluate_wrapper_policy,
    evaluate_scan_policy,
    should_block_on_partial_coverage,
)
from suscheck.services.summary_service import (
    build_scan_summary,
    build_explainability_trace,
    derive_coverage_contract,
    derive_modules_skipped,
)


def test_derive_modules_skipped_for_package_target() -> None:
    skipped = derive_modules_skipped(
        artifact_type="package",
        modules_ran=["tier0", "supply_chain"],
        file_path=None,
        mcp_dynamic_enabled=False,
    )

    assert "code" in skipped
    assert "config" in skipped
    assert "repo" in skipped
    assert "mcp" in skipped
    assert "ai_triage" in skipped


def test_derive_coverage_contract_from_pipeline_finding() -> None:
    findings = [
        Finding(
            module="pipeline",
            finding_id="PIPELINE-PACKAGE-STATIC-SKIPPED",
            title="Package static Tier 1 scanners were not executed",
            description="partial",
            severity=Severity.LOW,
            finding_type=FindingType.REVIEW_NEEDED,
            confidence=1.0,
            needs_human_review=True,
            review_reason="partial",
        )
    ]

    complete, notes = derive_coverage_contract(findings, modules_skipped=[])

    assert complete is False
    assert any("PIPELINE-PACKAGE-STATIC-SKIPPED" in note for note in notes)


def test_apply_partial_scan_safety_floor() -> None:
    findings = [
        Finding(
            module="pipeline",
            finding_id="PIPELINE-REPO-SCAN-SKIPPED",
            title="Repository static scan could not be completed",
            description="partial",
            severity=Severity.MEDIUM,
            finding_type=FindingType.REVIEW_NEEDED,
            confidence=1.0,
            needs_human_review=True,
            review_reason="partial",
        )
    ]
    pri = PRIScore(score=10, verdict=Verdict.CLEAR, breakdown=[])

    apply_partial_scan_safety_floor(pri, findings)

    assert pri.score == 16
    assert pri.verdict == Verdict.CAUTION


def test_build_summary_and_partial_gate() -> None:
    summary = build_scan_summary(
        target="requests",
        artifact_type="package",
        findings=[],
        pri_score=10,
        modules_ran=["supply_chain"],
        modules_skipped=["code"],
        coverage_complete=False,
        coverage_notes=["Modules skipped: code"],
    )

    assert summary.coverage_complete is False
    assert should_block_on_partial_coverage(summary, force=False) is True
    assert should_block_on_partial_coverage(summary, force=True) is False


def test_derive_coverage_contract_adds_mcp_phase_labels() -> None:
    complete, notes = derive_coverage_contract(
        findings=[],
        modules_skipped=[],
        artifact_type="mcp_server",
        modules_ran=["tier0", "mcp"],
        modules_failed=[],
        mcp_dynamic_enabled=False,
    )

    assert complete is True
    assert any(note.startswith("MCP-PHASE-A") for note in notes)
    assert any(note.startswith("MCP-PHASE-B") for note in notes)
    assert any(note.startswith("MCP-PHASE-C") for note in notes)
    assert any(note.startswith("MCP-PHASE-D") for note in notes)


def test_derive_coverage_contract_includes_dependency_db_state_note() -> None:
    findings = [
        Finding(
            module="dependency_check",
            finding_id="DEPCHK-DB-STATE",
            title="Dependency intelligence DB state: stale",
            description="status",
            severity=Severity.INFO,
            finding_type=FindingType.REVIEW_NEEDED,
            confidence=1.0,
            evidence={"dependency_db_state": "stale"},
        )
    ]

    complete, notes = derive_coverage_contract(findings=findings, modules_skipped=[])

    assert complete is True
    assert any("Dependency-Check DB state: stale" in note for note in notes)


def test_build_explainability_trace_includes_verdict_and_policy_context() -> None:
    summary = build_scan_summary(
        target="requests",
        artifact_type="package",
        findings=[
            Finding(
                module="code",
                finding_id="CODE-1",
                title="Code issue",
                description="test",
                severity=Severity.HIGH,
                finding_type=FindingType.SUSPICIOUS_BEHAVIOR,
                confidence=1.0,
            )
        ],
        pri_score=31,
        modules_ran=["supply_chain"],
        coverage_complete=False,
        coverage_notes=["Modules skipped: code"],
    )
    summary.policy_action = "warn"
    summary.policy_trace = ["coverage: block (scan coverage incomplete)"]
    summary.suppression_trace = ["suppression: active scope for alice matched 1 finding(s)"]

    trace = build_explainability_trace(summary)

    assert any(step.startswith("Verdict:") for step in trace)
    assert any(step.startswith("Top PRI drivers:") for step in trace)
    assert any("Policy gate action" in step for step in trace)
    assert any("Coverage / phase decisions:" in step for step in trace)


def test_evaluate_wrapper_policy_blocks_on_pri_without_force() -> None:
    summary = build_scan_summary(
        target="https://example.com/repo",
        artifact_type="repository",
        findings=[],
        pri_score=52,
        modules_ran=["repo"],
        coverage_complete=True,
    )

    decision = evaluate_wrapper_policy(summary, force=False, allow_pri_max=15)

    assert decision.block_partial_coverage is False
    assert decision.block_on_pri_threshold is True
    assert decision.warn_forced_override is False


def test_evaluate_wrapper_policy_warns_when_forced() -> None:
    summary = build_scan_summary(
        target="pypi:requests",
        artifact_type="package",
        findings=[],
        pri_score=61,
        modules_ran=["supply_chain"],
        coverage_complete=True,
    )

    decision = evaluate_wrapper_policy(summary, force=True, allow_pri_max=40)

    assert decision.block_partial_coverage is False
    assert decision.block_on_pri_threshold is False
    assert decision.warn_forced_override is True


def test_evaluate_scan_policy_blocks_on_partial_coverage() -> None:
    summary = build_scan_summary(
        target="requests",
        artifact_type="package",
        findings=[],
        pri_score=8,
        modules_ran=["supply_chain"],
        coverage_complete=False,
        coverage_notes=["Modules skipped: code"],
    )

    decision = evaluate_scan_policy(summary)

    assert decision.action == "block"
    assert any(step.startswith("coverage: block") for step in decision.trace)


def test_evaluate_scan_policy_warns_on_medium_pri() -> None:
    summary = build_scan_summary(
        target="requests",
        artifact_type="package",
        findings=[],
        pri_score=21,
        modules_ran=["supply_chain"],
        coverage_complete=True,
    )

    decision = evaluate_scan_policy(summary)

    assert decision.action == "warn"
    assert any(step.startswith("pri: warn") for step in decision.trace)
