"""Scan summary helpers extracted from CLI orchestration."""

from __future__ import annotations

import os

from suscheck.core.finding import Finding, ScanSummary, Severity, Verdict


def derive_modules_skipped(
    artifact_type: str,
    modules_ran: list[str],
    file_path: str | None,
    mcp_dynamic_enabled: bool,
) -> list[str]:
    """Infer skipped modules for reporting contract."""
    modules_skipped: list[str] = []
    artifact_lower = artifact_type.lower()

    if "package" in artifact_lower and "supply_chain" not in modules_ran:
        modules_skipped.append("supply_chain")
    if "package" in artifact_lower:
        for module_name in ["code", "config", "repo", "mcp"]:
            if module_name not in modules_ran:
                modules_skipped.append(module_name)
    if "ai_triage" not in modules_ran:
        modules_skipped.append("ai_triage")

    if file_path and os.path.isfile(file_path) and "mcp" not in modules_ran:
        modules_skipped.append("mcp")
    if file_path and os.path.isfile(file_path) and "mcp" in modules_ran and "mcp_dynamic" not in modules_ran:
        if not mcp_dynamic_enabled:
            modules_skipped.append("mcp_dynamic")

    return modules_skipped


def derive_coverage_contract(
    findings: list[Finding],
    modules_skipped: list[str],
    *,
    artifact_type: str | None = None,
    modules_ran: list[str] | None = None,
    modules_failed: list[str] | None = None,
    mcp_dynamic_enabled: bool | None = None,
) -> tuple[bool, list[str]]:
    """Build machine-readable coverage completeness flags and notes."""
    coverage_notes: list[str] = []
    blocking_notes: list[str] = []

    pipeline_partial_findings = [
        finding
        for finding in findings
        if finding.finding_id.startswith("PIPELINE-") and finding.needs_human_review
    ]
    for finding in pipeline_partial_findings:
        note = f"{finding.finding_id}: {finding.title}"
        coverage_notes.append(note)
        blocking_notes.append(note)

    dep_db_states = [
        str((finding.evidence or {}).get("dependency_db_state", "")).strip().lower()
        for finding in findings
        if finding.finding_id == "DEPCHK-DB-STATE"
    ]
    dep_db_states = [state for state in dep_db_states if state]
    if dep_db_states:
        coverage_notes.append(f"Dependency-Check DB state: {dep_db_states[0]}")

    non_optional_skips = [
        module_name for module_name in modules_skipped if module_name not in {"ai_triage", "mcp_dynamic"}
    ]
    if non_optional_skips:
        note = f"Modules skipped: {', '.join(sorted(set(non_optional_skips)))}"
        coverage_notes.append(note)
        blocking_notes.append(note)

    ran = set(modules_ran or [])
    failed = set(modules_failed or [])
    skipped = set(modules_skipped or [])
    artifact_lower = (artifact_type or "").lower()
    is_mcp_context = artifact_lower == "mcp_server" or "mcp" in ran or "mcp" in skipped

    if is_mcp_context:
        phase_a = "covered" if "mcp" in ran else "skipped"
        phase_b = "covered" if "mcp" in ran else "skipped"

        # Phase C source-level static analysis is optional and not yet split into a dedicated module.
        phase_c = "optional-not-enabled"

        if "mcp_dynamic" in failed:
            phase_d = "failed"
        elif "mcp_dynamic" in ran:
            phase_d = "covered"
        elif mcp_dynamic_enabled:
            phase_d = "optional-not-applicable"
        else:
            phase_d = "optional-disabled"

        coverage_notes.extend(
            [
                f"MCP-PHASE-A manifest-static: {phase_a}",
                f"MCP-PHASE-B auth-authz-static: {phase_b}",
                f"MCP-PHASE-C source-static: {phase_c}",
                f"MCP-PHASE-D runtime-dynamic: {phase_d}",
            ]
        )

    coverage_complete = len(blocking_notes) == 0
    return coverage_complete, coverage_notes


def build_scan_summary(
    target: str,
    artifact_type: str,
    findings: list[Finding],
    pri_score: int,
    modules_ran: list[str],
    modules_failed: list[str] | None = None,
    modules_skipped: list[str] | None = None,
    coverage_complete: bool = True,
    coverage_notes: list[str] | None = None,
    scan_duration: float = 0.0,
    vt_result: dict | None = None,
    trust_score: float | None = None,
    verdict: Verdict | None = None,
    pri_breakdown: list[str] | None = None,
) -> ScanSummary:
    """Build a ScanSummary from current scan state."""
    if verdict is None:
        if pri_score <= 15:
            verdict = Verdict.CLEAR
        elif pri_score <= 40:
            verdict = Verdict.CAUTION
        elif pri_score <= 70:
            verdict = Verdict.HOLD
        else:
            verdict = Verdict.ABORT

    return ScanSummary(
        target=target,
        artifact_type=artifact_type,
        pri_score=pri_score,
        verdict=verdict,
        findings=findings,
        total_findings=len(findings),
        critical_count=sum(1 for finding in findings if finding.severity == Severity.CRITICAL),
        high_count=sum(1 for finding in findings if finding.severity == Severity.HIGH),
        medium_count=sum(1 for finding in findings if finding.severity == Severity.MEDIUM),
        low_count=sum(1 for finding in findings if finding.severity == Severity.LOW),
        info_count=sum(1 for finding in findings if finding.severity == Severity.INFO),
        review_count=sum(1 for finding in findings if finding.needs_human_review),
        scan_duration=scan_duration,
        modules_ran=modules_ran,
        modules_failed=modules_failed or [],
        modules_skipped=modules_skipped or [],
        coverage_complete=coverage_complete,
        coverage_notes=coverage_notes or [],
        vt_result=vt_result,
        trust_score=trust_score,
        pri_breakdown=pri_breakdown or [],
    )
