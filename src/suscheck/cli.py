"""suscheck CLI — the main entry point."""

import logging
import os
import sys
import time
from pathlib import Path
from typing import Optional

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from suscheck import __version__
from suscheck.core.auto_detector import AutoDetector, Language
from suscheck.core.finding import Finding, FindingType, Severity, ReportFormat
from suscheck.core.risk_aggregator import RiskAggregator
from suscheck.services.policy_service import (
    apply_partial_scan_safety_floor,
    evaluate_wrapper_policy,
)
from suscheck.services.wrapper_service import (
    build_clone_failure_message,
    build_connect_result_panel,
    build_install_failure_message,
    execute_clone_wrapper,
    execute_install_wrapper,
    normalize_install_ecosystem,
)
from suscheck.services.summary_service import (
    build_scan_summary,
    derive_coverage_contract,
    derive_modules_skipped,
)
from suscheck.services.report_service import export_report
from suscheck.services.analysis_service import (
    execute_ai_triage_phase,
    execute_package_trust_phase,
)
from suscheck.modules.code.scanner import CodeScanner
from suscheck.modules.config.scanner import ConfigScanner
from suscheck.modules.mcp.dynamic import MCPDynamicScanner
from suscheck.modules.mcp.scanner import MCPScanner
from suscheck.modules.repo.scanner import RepoScanner
from suscheck.services.scan_service import (
    build_static_tier1_skip_findings,
    execute_local_file_tier1_phase,
    execute_remote_repository_tier1_phase,
    execute_semgrep_phase,
    execute_tier0_phase,
)
from suscheck.modules.reporting.terminal import (
    render_findings,
    render_scan_footer,
    render_scan_header,
    render_verdict,
)
from suscheck.core.pipeline import ScanPipeline
from suscheck.core.config_manager import ConfigManager
from suscheck.commands.aux_commands import register_aux_commands
from suscheck.commands.analysis_commands import register_analysis_commands

# ── Load .env file ────────────────────────────────────────────
# Searches for .env in the current directory and project root.
# Environment variables already set take precedence over .env.
_project_root = Path(__file__).resolve().parent.parent.parent
load_dotenv(_project_root / ".env")  # project root .env
load_dotenv()  # current directory .env (override)

app = typer.Typer(
    name="suscheck",
    help="SusCheck | Zero-Trust Pre-Execution Orchestrator. Audit before you execute.",
    epilog=(
        "Quick tips:\n"
        "  suscheck scan <target> -v\n"
        "  suscheck scan <target> --format html --output report.html\n"
        "  suscheck install pip <pkg> --force\n"
        "  suscheck diagnostics"
    ),
    no_args_is_help=True,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help", "-help"]},
)
console = Console()
detector = AutoDetector()


@app.command()
def scan(
    target: str = typer.Argument(help="File, directory, URL, or package name to scan"),
    report_format: ReportFormat = typer.Option(ReportFormat.TERMINAL, "--format", "-f", help="Output format: terminal, markdown, html, json"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="File to save the report to"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Skip AI triage, rules-only mode"),
    upload_vt: bool = typer.Option(
        False, "--upload-vt",
        help="Upload file to VirusTotal if hash unknown. ⚠️  File becomes PUBLIC on VT.",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", "-V", help="Verbose output"),
    mcp_dynamic: bool = typer.Option(
        False,
        "--mcp-dynamic",
        help="After static MCP scan, run optional Docker observation (requires docker package + daemon).",
    ),
    report_dir: Optional[Path] = typer.Option(
        None, "--report-dir", help="Directory to save reports to (defaults to ./reports/)"
    ),
):
    """Scan any artifact for security issues."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(name)s: %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING)

    scan_start = time.time()

    # --- Step 0: Auto-Detection (Immediate) ---
    target_path = Path(target).resolve()
    config_mgr = ConfigManager()
    
    # Global Existence Check
    if not target_path.exists() and not any(target.startswith(p) for p in ["http://", "https://"]):
         # Check if it might be a package name (no dots, no slashes)
         is_likely_package = "/" not in target and "\\" not in target and "." not in target
         if not is_likely_package:
             console.print(f"\n[bold red]FATAL: Artifact not found at source:[/bold red] {target}")
             console.print("[dim]Ensure the path is correct or specify a valid package name.[/dim]")
             sys.exit(1)

    detector = AutoDetector(config_mgr)
    detection = detector.detect(target)
    
    # --- Step 1: Render Header ---
    type_display = f"{detection.artifact_type.value.upper()}"
    if detection.language != Language.UNKNOWN:
        type_display += f" ({detection.language.value.capitalize()})"
        
    render_scan_header(target, type_display, __version__)

    pipeline = ScanPipeline(config_mgr)

    if target_path.is_dir():
        console.print(f"\n[bold blue]Recursive directory scan initiated:[/bold blue] {target}")
        
        with console.status(f"Scanning directory {target}...", spinner="bouncingBar"):
            all_findings = pipeline.scan_directory(target)
        
        modules_ran = pipeline.get_modules_ran(all_findings)
        scan_duration = time.time() - scan_start
        
        aggregator = RiskAggregator("DIRECTORY")
        pri_result = aggregator.calculate(all_findings)
        
        summary = build_scan_summary(
            target=target,
            artifact_type="DIRECTORY",
            findings=all_findings,
            pri_score=pri_result.score,
            modules_ran=list(modules_ran),
            scan_duration=scan_duration,
            verdict=pri_result.verdict,
            pri_breakdown=pri_result.breakdown
        )
        
        console.print(Panel("\n".join(pri_result.breakdown), title="Heuristic Risk Vector Analysis", border_style="dim"))
        render_findings(all_findings)
        render_verdict(summary)
        render_scan_footer(summary)
        
        if report_format != ReportFormat.TERMINAL:
            use_timestamp = config_mgr.get("reporting.timestamped", True)
            report_path = export_report(
                summary=summary,
                target=target,
                report_format=report_format,
                output=output,
                report_dir=report_dir,
                default_report_dir=config_mgr.get("reporting.default_dir"),
                use_timestamp=use_timestamp,
            )
            if report_path:
                console.print(f"\n[bold green]✓[/bold green] Directory report saved: [cyan]{report_path}[/cyan]")
             
        return summary

    # ── Step 1: Auto-detect artifact type (Existing Single File Mode) ───────────
    detection = detector.detect(target)

    table = Table(title="Detection Result", border_style="blue")
    table.add_column("Property", style="bold")
    table.add_column("Value")

    table.add_row("Artifact Type", f"[cyan]{detection.artifact_type.value}[/cyan]")
    table.add_row("Language/Format", f"[green]{detection.language.value}[/green]")
    table.add_row("Detection Method", detection.detection_method)
    table.add_row("Confidence", f"{detection.confidence:.0%}")
    table.add_row("File Path", str(detection.file_path))

    if detection.magic_description:
        table.add_row("Magic Description", detection.magic_description)

    if detection.is_polyglot:
        langs = ", ".join(l.value for l in detection.secondary_languages)
        table.add_row(
            "[yellow]⚠️ Polyglot[/yellow]",
            f"[yellow]Also detected as: {langs}[/yellow]",
        )

    if detection.type_mismatch:
        table.add_row("[red]🚨 Mismatch[/red]", f"[red]{detection.mismatch_detail}[/red]")

    console.print(table)

    # ── Mismatch / Polyglot → generate Findings ──────────────
    all_findings: list[Finding] = []

    if detection.type_mismatch:
        all_findings.append(Finding(
            module="auto_detector",
            finding_id="DETECT-MISMATCH",
            title=f"File type mismatch: {detection.mismatch_detail}",
            description=(
                "The file extension does not match the actual file type detected "
                "by magic bytes. This is a common malware evasion technique "
                "(e.g., renaming an EXE to .txt)."
            ),
            severity=Severity.HIGH,
            finding_type=FindingType.FILE_MISMATCH,
            confidence=0.90,
            file_path=str(detection.file_path),
            mitre_ids=["T1036.008"],  # Masquerading: Match Legitimate Resource
            evidence={
                "mismatch_detail": detection.mismatch_detail,
                "detection_method": detection.detection_method,
            },
        ))

    if detection.is_polyglot:
        secondary = ", ".join(l.value for l in detection.secondary_languages)
        all_findings.append(Finding(
            module="auto_detector",
            finding_id="DETECT-POLYGLOT",
            title=f"Polyglot file detected (also: {secondary})",
            description=(
                f"This file is valid in multiple formats: {detection.language.value} "
                f"and {secondary}. Polyglot files can hide malicious payloads."
            ),
            severity=Severity.MEDIUM,
            finding_type=FindingType.POLYGLOT,
            confidence=0.70,
            file_path=str(detection.file_path),
            mitre_ids=["T1027.009"],  # Obfuscated Files: Embedded Payloads
            needs_human_review=True,
            review_reason="Polyglot file — scan as all detected types",
        ))

    # ── Step 2: Tier 0 — Hash & Reputation ────────────────────
    file_path = detection.file_path
    tier0_phase = execute_tier0_phase(
        target=target,
        detection=detection,
        upload_vt=upload_vt,
        scan_start=scan_start,
        console=console,
    )
    if tier0_phase.short_circuit_summary is not None:
        return tier0_phase.short_circuit_summary

    all_findings.extend(tier0_phase.findings)
    vt_dict = tier0_phase.vt_dict
    modules_ran = tier0_phase.modules_ran

    # ── Remaining modules (Tier 1, Tier 2) ────────────────────
    if file_path and os.path.isfile(str(file_path)):
        tier1_findings, modules_ran = execute_local_file_tier1_phase(
            file_path=str(file_path),
            detection=detection,
            modules_ran=modules_ran,
            console=console,
        )
        if tier1_findings:
            all_findings.extend(tier1_findings)

        if (
            mcp_dynamic
            and file_path
            and os.path.isfile(str(file_path))
            and "mcp" in modules_ran
        ):
            try:
                dyn = MCPDynamicScanner()
                if dyn.can_handle(detection.artifact_type.value, str(file_path)):
                    console.print("\n[bold]MCP Dynamic (Docker)[/bold]")
                    dyn_res = dyn.scan(str(file_path))
                    modules_ran.append("mcp_dynamic")
                    all_findings.extend(dyn_res.findings)
                    if dyn_res.error:
                        console.print(f"  [dim]MCP dynamic: {dyn_res.error}[/dim]")
                    for note in dyn_res.metadata.get("observations") or []:
                        if note.get("error"):
                            console.print(f"  [dim]  server {note.get('server')}: {note['error']}[/dim]")
                        elif note.get("skip"):
                            console.print(
                                f"  [dim]  server {note.get('server')}: skipped ({note['skip']})[/dim]"
                            )
                    if dyn_res.findings:
                        render_findings(dyn_res.findings)
                    elif not dyn_res.error:
                        console.print(
                            "  [dim]MCP dynamic finished (no findings from observation).[/dim]"
                        )
            except Exception as e:
                console.print(f"  [yellow]MCP dynamic observation failed: {e}[/yellow]")

        semgrep_findings = execute_semgrep_phase(file_path=str(file_path), console=console)
        if semgrep_findings:
            all_findings.extend(semgrep_findings)

    elif detection.artifact_type.value == "repository" and target.startswith(("http://", "https://", "git@")):
        repo_findings, modules_ran = execute_remote_repository_tier1_phase(
            target=target,
            pipeline=pipeline,
            modules_ran=modules_ran,
            console=console,
        )
        all_findings.extend(repo_findings)
    else:
        console.print("\n[bold]Tier 1: Static Analysis[/bold]")
        console.print("  [dim]Tier 1 skipped: static scanners currently require a local file or repository target.[/dim]")
        all_findings.extend(
            build_static_tier1_skip_findings(target=target, artifact_type=detection.artifact_type.value)
        )


    # ── Final verdict ─────────────────────────────────────────
    scan_duration = time.time() - scan_start

    supply_chain_trust_score, trust_findings, modules_ran = execute_package_trust_phase(
        target=target,
        artifact_type=detection.artifact_type.value,
        modules_ran=modules_ran,
        console=console,
    )
    if trust_findings:
        all_findings.extend(trust_findings)

    ai_pri_delta, modules_ran = execute_ai_triage_phase(
        no_ai=no_ai,
        findings=all_findings,
        target=target,
        artifact_type=detection.artifact_type.value,
        modules_ran=modules_ran,
        console=console,
    )

    aggregator = RiskAggregator(detection.artifact_type.value)
    pri_result = aggregator.calculate(
        all_findings,
        vt_dict,
        ai_pri_delta=ai_pri_delta,
        trust_score=supply_chain_trust_score,
    )

    apply_partial_scan_safety_floor(pri_result, all_findings)

    modules_skipped = derive_modules_skipped(
        artifact_type=detection.artifact_type.value,
        modules_ran=modules_ran,
        file_path=str(file_path) if file_path else None,
        mcp_dynamic_enabled=mcp_dynamic,
    )
    coverage_complete, coverage_notes = derive_coverage_contract(all_findings, modules_skipped)

    summary = build_scan_summary(
        target=target,
        artifact_type=detection.artifact_type.value,
        findings=all_findings,
        pri_score=pri_result.score,
        modules_ran=modules_ran,
        modules_skipped=modules_skipped,
        coverage_complete=coverage_complete,
        coverage_notes=coverage_notes,
        scan_duration=scan_duration,
        vt_result=vt_dict,
        trust_score=supply_chain_trust_score,
        verdict=pri_result.verdict,
        pri_breakdown=pri_result.breakdown,
    )
    
    # Render the detailed breakdown from RiskAggregator
    console.print(Panel(
        "\n".join(pri_result.breakdown),
        title="Score Explanation",
        border_style="dim",
        padding=(0, 2),
    ))
    
    render_verdict(summary)
    render_scan_footer(summary)

    # ── Step 11: Export Report ───────────────────────────────────────────
    if report_format != ReportFormat.TERMINAL:
        use_timestamp = config_mgr.get("reporting.timestamped", True)
        try:
            report_path = export_report(
                summary=summary,
                target=target,
                report_format=report_format,
                output=output,
                report_dir=report_dir,
                default_report_dir=config_mgr.get("reporting.default_dir"),
                use_timestamp=use_timestamp,
            )
            if report_path:
                console.print(f"\n[bold green]✓[/bold green] Report saved to: [cyan]{report_path}[/cyan]")
        except Exception as e:
            console.print(f"\n[bold red]✗[/bold red] Failed to save report: {e}")

    return summary

@app.command()
def install(
    ecosystem: str = typer.Argument(help="Package manager: pip, npm"),
    package: str = typer.Argument(help="Package to scan and install"),
    force: bool = typer.Option(False, "--force", help="Install even if scan finds issues"),
):
    """Scan a package, then install it if safe."""
    console.print("\n[bold blue]sus check install[/bold blue]")
    console.print(f"Package: [yellow]{package}[/yellow] via {ecosystem}")

    # Normalize ecosystem for trust/scan target vs installer command.
    trust_ecosystem = normalize_install_ecosystem(ecosystem)
    if trust_ecosystem is None:
        console.print(f"[red]Unsupported ecosystem:[/red] {ecosystem}")
        raise typer.Exit(1)

    # For packages, we prefer the ecosystem-qualified form so the TrustEngine
    # can reuse it (e.g. ``pypi:requests`` or ``npm:lodash``).
    scan_target = f"{trust_ecosystem}:{package}"

    console.print("\n[dim]Scanning package before install...[/dim]")
    summary = scan(
        target=scan_target,
        report_format=ReportFormat.TERMINAL,
        output=None,
        no_ai=False,
        upload_vt=False,
        verbose=False,
        mcp_dynamic=False,
        report_dir=None,
    )

    install_policy = evaluate_wrapper_policy(summary, force=force, allow_pri_max=40)

    if install_policy.block_partial_coverage:
        console.print(
            Panel(
                (
                    "[bold red]Installation blocked by SusCheck.[/bold red]\n\n"
                    "Scan coverage is partial, so install is blocked by policy.\n"
                    "Review coverage notes and findings before trusting this package.\n\n"
                    f"Coverage notes:\n- " + "\n- ".join(summary.coverage_notes)
                ),
                title="🚫 Install Blocked (Partial Coverage)",
                border_style="red",
                padding=(1, 2),
            )
        )
        raise typer.Exit(1)

    # Block installs when PRI is above the CAUTION band unless --force is used.
    if install_policy.block_on_pri_threshold:
        verdict_label = summary.verdict.value.upper()
        console.print(
            Panel(
                (
                    "[bold red]Installation blocked by SusCheck.[/bold red]\n\n"
                    f"Platform Risk Index: [bold]{summary.pri_score}/100[/bold] ({verdict_label}).\n"
                    "Threshold for safe install is PRI ≤ 40.\n\n"
                    "Review the findings above before trusting this package.\n"
                    "If you still wish to proceed, re-run with [yellow]--force[/yellow]."
                ),
                title="🚫 Install Blocked",
                border_style="red",
                padding=(1, 2),
            )
        )
        raise typer.Exit(1)

    if install_policy.warn_forced_override:
        console.print(
            Panel(
                (
                    "[bold red]WARNING:[/bold red] Proceeding with install despite high PRI score "
                    f"({summary.pri_score}/100, {summary.verdict.value.upper()}) "
                    "because [yellow]--force[/yellow] was specified."
                ),
                border_style="red",
                padding=(1, 1),
            )
        )

    # Execute the actual install command using modular wrapper.
    console.print("\n[bold]Executing installation...[/bold]\n")
    return_code = execute_install_wrapper(trust_ecosystem=trust_ecosystem, package=package)

    if return_code != 0:
        console.print(f"[red]{build_install_failure_message(return_code)}[/red]")
        raise typer.Exit(return_code)


@app.command()
def clone(
    url: str = typer.Argument(help="Repository URL to scan and clone"),
    dest: str = typer.Option(None, "--dest", "-d", help="Clone destination"),
    force: bool = typer.Option(False, "--force", help="Clone even if scan finds issues"),
):
    """Scan a repository, then clone it if safe."""
    console.print("\n[bold blue]sus check clone[/bold blue]")
    console.print(f"Repository: [yellow]{url}[/yellow]")

    console.print("\n[dim]Scanning repository URL before clone...[/dim]")
    summary = scan(
        target=url,
        report_format=ReportFormat.TERMINAL,
        output=None,
        no_ai=False,
        upload_vt=False,
        verbose=False,
        mcp_dynamic=False,
        report_dir=None,
    )

    clone_policy = evaluate_wrapper_policy(summary, force=force, allow_pri_max=15)

    if clone_policy.block_partial_coverage:
        console.print(
            Panel(
                (
                    "[bold red]Clone blocked by SusCheck.[/bold red]\n\n"
                    "Scan coverage is partial, so clone is blocked by policy.\n"
                    "Review coverage notes and findings before cloning this repository.\n\n"
                    f"Coverage notes:\n- " + "\n- ".join(summary.coverage_notes)
                ),
                title="🚫 Clone Blocked (Partial Coverage)",
                border_style="red",
                padding=(1, 2),
            )
        )
        raise typer.Exit(1)

    # Block clone when PRI indicates anything other than CLEAR, unless forced.
    if clone_policy.block_on_pri_threshold:
        verdict_label = summary.verdict.value.upper()
        console.print(
            Panel(
                (
                    "[bold red]Clone blocked by SusCheck.[/bold red]\n\n"
                    f"Platform Risk Index: [bold]{summary.pri_score}/100[/bold] ({verdict_label}).\n"
                    "Only CLEAR repositories (PRI ≤ 15) are allowed by default.\n\n"
                    "Review findings above before cloning this repository.\n"
                    "If you still wish to proceed, re-run with [yellow]--force[/yellow]."
                ),
                title="🚫 Clone Blocked",
                border_style="red",
                padding=(1, 2),
            )
        )
        raise typer.Exit(1)

    if clone_policy.warn_forced_override:
        console.print(
            Panel(
                (
                    "[bold red]WARNING:[/bold red] Proceeding with clone despite elevated PRI score "
                    f"({summary.pri_score}/100, {summary.verdict.value.upper()}) "
                    "because [yellow]--force[/yellow] was specified."
                ),
                border_style="red",
                padding=(1, 1),
            )
        )

    # Execute `git clone` using modular wrapper.
    console.print("\n[bold]Executing git clone...[/bold]\n")
    return_code = execute_clone_wrapper(url=url, dest=dest)

    if return_code != 0:
        console.print(f"[red]{build_clone_failure_message(return_code)}[/red]")
        raise typer.Exit(return_code)


@app.command()
def connect(
    server: str = typer.Argument(help="MCP server URL or manifest path"),
    force: bool = typer.Option(False, "--force", help="Connect even if scan finds issues"),
):
    """Scan an MCP server, then provide connection config if safe."""
    console.print("\n[bold blue]sus check connect[/bold blue]")
    console.print(f"MCP Server: [yellow]{server}[/yellow]")

    console.print("\n[dim]Scanning MCP server target before connection...[/dim]")
    summary = scan(
        target=server,
        report_format=ReportFormat.TERMINAL,
        output=None,
        no_ai=False,
        upload_vt=False,
        verbose=False,
        mcp_dynamic=False,
        report_dir=None,
    )

    connect_policy = evaluate_wrapper_policy(summary, force=force, allow_pri_max=15)

    if connect_policy.block_partial_coverage:
        console.print(
            Panel(
                (
                    "[bold red]Connection blocked by SusCheck.[/bold red]\n\n"
                    "Scan coverage is partial, so MCP connection is blocked by policy.\n"
                    "Review coverage notes and findings before connecting this server.\n\n"
                    f"Coverage notes:\n- " + "\n- ".join(summary.coverage_notes)
                ),
                title="🚫 Connect Blocked (Partial Coverage)",
                border_style="red",
                padding=(1, 2),
            )
        )
        raise typer.Exit(1)

    # For MCP connections we mirror the repo policy: only CLEAR is allowed
    # by default; anything higher requires explicit human override.
    if connect_policy.block_on_pri_threshold:
        verdict_label = summary.verdict.value.upper()
        console.print(
            Panel(
                (
                    "[bold red]Connection blocked by SusCheck.[/bold red]\n\n"
                    f"Platform Risk Index: [bold]{summary.pri_score}/100[/bold] ({verdict_label}).\n"
                    "Only CLEAR MCP endpoints (PRI ≤ 15) are allowed by default.\n\n"
                    "Review the findings above before wiring this server into your client.\n"
                    "If you still wish to proceed, re-run with [yellow]--force[/yellow]."
                ),
                title="🚫 Connect Blocked",
                border_style="red",
                padding=(1, 2),
            )
        )
        raise typer.Exit(1)

    console.print(
        build_connect_result_panel(
            server=server,
            pri_score=summary.pri_score,
            verdict_label=summary.verdict.value.upper(),
            force=connect_policy.warn_forced_override,
        )
    )


register_aux_commands(app, console=console, version=__version__)
register_analysis_commands(app, console=console, detector=detector, version=__version__)


if __name__ == "__main__":
    app()
