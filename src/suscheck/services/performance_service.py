"""Performance guardrail helpers for profile-based scan duration tracking."""

from __future__ import annotations

from dataclasses import dataclass

from suscheck.core.finding import Finding, FindingType, Severity, ScanSummary


_PROFILE_GUARDRAILS = {
    "default": 30.0,
    "deep": 60.0,
    "fast": 15.0,
    "mcp-hardening": 25.0,
}


@dataclass(frozen=True)
class PerformanceGuardrailResult:
    findings: list[Finding]
    trace: list[str]
    threshold_seconds: float | None


def evaluate_performance_guardrails(*, profile: str, summary: ScanSummary) -> PerformanceGuardrailResult:
    """Compare scan duration against a deterministic profile guardrail."""
    profile_key = profile.strip().lower()
    threshold = _PROFILE_GUARDRAILS.get(profile_key)
    trace: list[str] = []
    findings: list[Finding] = []

    if threshold is None:
        trace.append(f"performance: no guardrail configured for profile '{profile_key}'")
        return PerformanceGuardrailResult(findings=findings, trace=trace, threshold_seconds=None)

    if summary.scan_duration > threshold:
        trace.append(
            f"performance: regression ({summary.scan_duration:.2f}s > {threshold:.2f}s guardrail for {profile_key})"
        )
        findings.append(
            Finding(
                module="governance",
                finding_id="PERF-REGRESSION",
                title=f"Scan time exceeded {profile_key} guardrail",
                description=(
                    "The scan duration exceeded the profile guardrail. This is an operational signal, "
                    "not a security verdict change, and should be reviewed for performance regression."
                ),
                severity=Severity.INFO,
                finding_type=FindingType.REVIEW_NEEDED,
                confidence=0.95,
                evidence={
                    "profile": profile_key,
                    "scan_duration_seconds": round(summary.scan_duration, 2),
                    "threshold_seconds": threshold,
                },
                needs_human_review=False,
            )
        )
    else:
        trace.append(
            f"performance: within guardrail ({summary.scan_duration:.2f}s <= {threshold:.2f}s for {profile_key})"
        )

    return PerformanceGuardrailResult(findings=findings, trace=trace, threshold_seconds=threshold)
