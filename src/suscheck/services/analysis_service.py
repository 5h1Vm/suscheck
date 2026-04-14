"""Analysis orchestration helpers extracted from CLI."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel

from suscheck.core.errors import AnalysisPhaseError, get_error_code
from suscheck.core.finding import Finding, FindingType, Severity
from suscheck.modules.reporting.terminal import render_findings


def execute_package_trust_phase(
    *,
    target: str,
    artifact_type: str,
    modules_ran: list[str],
    console: Console,
) -> tuple[float | None, list[Finding], list[str]]:
    """Run package trust checks and return score/findings/module updates."""
    modules_updated = list(modules_ran)
    if "package" not in artifact_type.lower():
        return None, [], modules_updated

    from suscheck.modules.supply_chain.trust_engine import TrustEngine

    trust_engine = TrustEngine()
    if ":" in target:
        full_target = target
    else:
        full_target = f"pypi:{target}"

    with console.status(
        f"Querying supply chain trust for {full_target}...",
        spinner="dots",
    ):
        try:
            trust_res = trust_engine.scan(full_target)
        except (OSError, RuntimeError, ValueError, TypeError) as e:
            err = AnalysisPhaseError(
                f"Supply chain trust lookup failed for {full_target}: {e}",
                code="ANALYSIS_PACKAGE_TRUST_FAILED",
            )
            console.print(f"[yellow]Supply chain trust scan skipped [{err.code}]:[/yellow] {err}")
            return None, [], modules_updated

    if trust_res.error:
        console.print(f"[yellow]Supply chain trust scan skipped:[/yellow] {trust_res.error}")
        return None, [], modules_updated

    if "supply_chain" not in modules_updated:
        modules_updated.append("supply_chain")

    return trust_res.trust_score, (trust_res.findings or []), modules_updated


def execute_ai_triage_phase(
    *,
    no_ai: bool,
    findings: list[Finding],
    target: str,
    artifact_type: str,
    modules_ran: list[str],
    console: Console,
) -> tuple[float, list[str]]:
    """Run AI triage phase and return PRI adjustment plus module updates."""
    modules_updated = list(modules_ran)
    if no_ai or not findings:
        return 0.0, modules_updated

    from suscheck.ai.triage_engine import run_ai_triage

    try:
        tres = run_ai_triage(
            findings,
            target=target,
            artifact_type=artifact_type,
            console=console,
        )
    except (OSError, RuntimeError, ValueError, TypeError) as e:
        err = AnalysisPhaseError(
            f"AI triage execution failed for {target}: {e}",
            code="ANALYSIS_AI_TRIAGE_FAILED",
        )
        console.print(f"[yellow]AI triage skipped [{err.code}]:[/yellow] {err}")
        return 0.0, modules_updated

    if tres.ran and "ai_triage" not in modules_updated:
        modules_updated.append("ai_triage")
        note_lines = [
            f"[bold]{finding.finding_id}[/bold]: {finding.ai_explanation}"
            for finding in findings
            if finding.ai_explanation
        ]
        if note_lines:
            console.print(
                Panel(
                    "\n\n".join(note_lines[:24]),
                    title="AI Triage",
                    border_style="magenta",
                )
            )

    return float(tres.pri_adjustment), modules_updated


def execute_explain_indicator_phase(*, file: str, detection, console: Console) -> list[Finding]:
    """Collect static indicators for `explain` command using the same baseline scan flow."""
    findings: list[Finding] = []

    with console.status("[bold blue]Gathering scan indicators...[/bold blue]"):
        if detection.type_mismatch:
            findings.append(
                Finding(
                    module="auto_detector",
                    finding_id="DETECT-MISMATCH",
                    title="File type mismatch",
                    description=f"File extension mismatch: {detection.mismatch_detail}",
                    severity=Severity.HIGH,
                    finding_type=FindingType.FILE_MISMATCH,
                    confidence=0.9,
                    file_path=file,
                )
            )

        from suscheck.modules.external.engine import Tier0Engine

        tier0 = Tier0Engine()
        t0_res = tier0.check_file(file)
        findings.extend(t0_res.findings)

        if detection.artifact_type.value == "code":
            from suscheck.modules.code.scanner import CodeScanner

            code_scanner = CodeScanner()
            c_res = code_scanner.scan_file(file)
            findings.extend(c_res.findings)

        if detection.is_polyglot:
            findings.append(
                Finding(
                    module="auto_detector",
                    finding_id="DETECT-POLYGLOT",
                    title="Polyglot file",
                    description="File is valid in multiple formats.",
                    severity=Severity.MEDIUM,
                    finding_type=FindingType.FILE_MISMATCH,
                    confidence=0.8,
                    file_path=file,
                )
            )

        try:
            from suscheck.modules.semgrep_runner import SemgrepRunner

            semgrep = SemgrepRunner()
            if semgrep.is_installed:
                s_res = semgrep.scan_file(file)
                findings.extend(s_res.findings)
        except (ImportError, OSError, RuntimeError, ValueError, TypeError) as e:
            code = get_error_code(e, "ANALYSIS_SEMGREP_ORCHESTRATION_FAILED")
            console.print(f"[dim]Semgrep indicator phase skipped [{code}]: {e}[/dim]")

    if findings:
        console.print(
            "[bold cyan]🔍 Investigative Brain: Gathered Security Indicators (Tier 0/1 Static Analysis):[/bold cyan]"
        )
        render_findings(findings)
    else:
        console.print("[dim]No static indicators (Tier 0/1) found in baseline scan.[/dim]")

    return findings
