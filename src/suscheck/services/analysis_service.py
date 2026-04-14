"""Analysis orchestration helpers extracted from CLI."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel

from suscheck.core.finding import Finding


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
        trust_res = trust_engine.scan(full_target)

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

    tres = run_ai_triage(
        findings,
        target=target,
        artifact_type=artifact_type,
        console=console,
    )

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
