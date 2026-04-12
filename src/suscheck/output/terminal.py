"""Rich terminal output renderer."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from suscheck.core.finding import Finding, FindingType, ScanSummary, Severity, Verdict

console = Console()

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "🚫",
    Severity.HIGH: "🔶",
    Severity.MEDIUM: "⚠️",
    Severity.LOW: "ℹ️",
    Severity.INFO: "·",
}

VERDICT_DISPLAY = {
    Verdict.CLEAR: ("✅ CLEAR", "bold green"),
    Verdict.CAUTION: ("⚠️ CAUTION", "bold yellow"),
    Verdict.HOLD: ("🔶 HOLD", "bold orange1"),
    Verdict.ABORT: ("🚫 ABORT", "bold red"),
}


def render_scan_header(target: str, artifact_type: str, version: str) -> None:
    """Render scan header."""
    console.print(f"\n[bold blue]sus check[/bold blue] v{version}")
    console.print(f"Target: [yellow]{target}[/yellow]")
    console.print(f"Type:   [cyan]{artifact_type}[/cyan]\n")


def render_verdict(summary: ScanSummary) -> None:
    """Render the big verdict panel."""
    verdict_text, verdict_style = VERDICT_DISPLAY[summary.verdict]

    score_bar = _build_score_bar(summary.pri_score)

    content = (
        f"[{verdict_style}]{verdict_text}[/{verdict_style}]\n\n"
        f"Platform Risk Index: [{verdict_style}]{summary.pri_score}/100[/{verdict_style}]\n"
        f"{score_bar}\n\n"
        f"Findings: {summary.critical_count} critical · {summary.high_count} high · "
        f"{summary.medium_count} medium · {summary.low_count} low · {summary.info_count} info"
    )

    if summary.review_count > 0:
        content += f"\n🔍 {summary.review_count} item(s) need human review"

    if summary.trust_score is not None:
        content += f"\nSupply Chain Trust: {summary.trust_score:.1f}/10"

    border = "green" if summary.verdict == Verdict.CLEAR else (
        "yellow" if summary.verdict == Verdict.CAUTION else (
            "orange1" if summary.verdict == Verdict.HOLD else "red"
        )
    )

    console.print(Panel(content, title="Scan Verdict", border_style=border, padding=(1, 2)))


def render_findings(findings: list[Finding]) -> None:
    """Render findings table."""
    if not findings:
        console.print("[green]No security findings detected.[/green]\n")
        return

    # Separate review items and regular findings
    reviews = [f for f in findings if f.needs_human_review]
    regular_raw = [f for f in findings if not f.needs_human_review]

    # False-positive / low-confidence display filter:
    # - Keep all findings in scoring, but do not show low-confidence items
    #   as primary alerts.
    # - Items explicitly marked for review are always shown.
    primary: list[Finding] = []
    low_confidence: list[Finding] = []
    for f in regular_raw:
        if f.confidence is not None and f.confidence < 0.4 and f.finding_type != FindingType.REVIEW_NEEDED:
            low_confidence.append(f)
        else:
            primary.append(f)

    if primary:
        table = Table(
            title="Findings",
            box=box.ROUNDED,
            border_style="blue",
            show_lines=True,
        )
        table.add_column("Sev", width=4, justify="center")
        table.add_column("Finding", min_width=40)
        table.add_column("Location", min_width=15)
        table.add_column("MITRE", min_width=10)

        for f in sorted(primary, key=lambda x: list(Severity).index(x.severity)):
            icon = SEVERITY_ICONS[f.severity]
            color = SEVERITY_COLORS[f.severity]

            location = ""
            if f.file_path and f.line_number:
                location = f"{f.file_path}:{f.line_number}"
            elif f.file_path:
                location = f.file_path

            mitre = ", ".join(f.mitre_ids) if f.mitre_ids else "—"

            detail = f.description
            if f.ai_explanation:
                detail += f"\n[magenta]AI[/magenta] [dim]{f.ai_explanation}[/dim]"
            if f.ai_false_positive:
                detail += "\n[green]AI: likely false positive[/green]"

            table.add_row(
                f"[{color}]{icon}[/{color}]",
                f"[{color}]{f.title}[/{color}]\n[dim]{detail}[/dim]",
                f"[dim]{location}[/dim]",
                f"[dim]{mitre}[/dim]",
            )

        console.print(table)

    if low_confidence:
        lc_table = Table(
            title="Low Confidence Indicators",
            box=box.SIMPLE,
            border_style="dim",
            show_lines=False,
        )
        lc_table.add_column("Sev", width=4, justify="center")
        lc_table.add_column("Finding", min_width=40)

        for f in sorted(low_confidence, key=lambda x: list(Severity).index(x.severity)):
            icon = SEVERITY_ICONS[f.severity]
            color = SEVERITY_COLORS[f.severity]
            detail = f.description
            lc_table.add_row(
                f"[{color}]{icon}[/{color}]",
                f"[{color}]{f.title}[/{color}]\n[dim]{detail}[/dim] (conf {f.confidence:.2f})",
            )

        console.print(lc_table)

    if reviews:
        console.print()
        review_panel_content = ""
        for f in reviews:
            location = ""
            if f.file_path and f.line_number:
                location = f" ({f.file_path}:{f.line_number})"

            review_panel_content += (
                f"🔍 [bold]{f.title}[/bold]{location}\n"
                f"   [dim]{f.review_reason or f.description}[/dim]\n\n"
            )

        review_panel_content += (
            "[dim]The tool could not fully classify these items.\n"
            "They may be benign or malicious. Manual review needed.[/dim]"
        )

        console.print(Panel(
            review_panel_content,
            title="🔍 Needs Human Review",
            border_style="yellow",
            padding=(1, 2),
        ))


def render_code_snippet(finding: Finding) -> None:
    """Render a code snippet for a finding."""
    if not finding.code_snippet:
        return

    console.print(Panel(
        f"[dim]{finding.code_snippet}[/dim]",
        title=f"Line {finding.line_number or '?'}",
        border_style="dim",
    ))


def render_vt_result(vt_result: dict) -> None:
    """Render VirusTotal results."""
    if not vt_result:
        return

    if not vt_result.get("found"):
        console.print("[dim]VirusTotal: Hash not found (first-seen artifact)[/dim]\n")
        return

    detections = vt_result.get("detection_count", 0)
    total = vt_result.get("total_engines", 0)

    if detections == 0:
        style = "green"
        icon = "✅"
    elif detections <= 3:
        style = "yellow"
        icon = "⚠️"
    elif detections <= 10:
        style = "orange1"
        icon = "🔶"
    else:
        style = "red"
        icon = "🚫"

    content = f"{icon} [{style}]{detections}/{total} engines flagged this file[/{style}]"

    if vt_result.get("detection_names"):
        names = ", ".join(vt_result["detection_names"][:5])
        content += f"\n[dim]Detections: {names}[/dim]"

    if vt_result.get("vt_link"):
        content += f"\n[dim]Details: {vt_result['vt_link']}[/dim]"

    console.print(Panel(content, title="VirusTotal", border_style=style))


def render_scan_footer(summary: ScanSummary) -> None:
    """Render scan footer with timing and module info."""
    modules = ", ".join(summary.modules_ran) if summary.modules_ran else "none"
    skipped = ", ".join(summary.modules_skipped) if summary.modules_skipped else "none"

    console.print(
        f"\n[dim]Scan completed in {summary.scan_duration:.2f}s | "
        f"Modules: {modules} | Skipped: {skipped}[/dim]\n"
    )


def _build_score_bar(score: int, width: int = 30) -> str:
    """Build a visual score bar."""
    filled = int((score / 100) * width)
    empty = width - filled

    if score <= 15:
        color = "green"
    elif score <= 40:
        color = "yellow"
    elif score <= 70:
        color = "orange1"
    else:
        color = "red"

    bar = f"[{color}]{'█' * filled}[/{color}][dim]{'░' * empty}[/dim]"
    return bar
