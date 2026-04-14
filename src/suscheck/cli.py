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
from suscheck.services.policy_service import apply_partial_scan_safety_floor, should_block_on_partial_coverage
from suscheck.services.summary_service import (
    build_scan_summary,
    derive_coverage_contract,
    derive_modules_skipped,
)
from suscheck.services.report_service import export_report
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
import shutil
from suscheck.core.config_manager import ConfigManager
from suscheck.modules.wrappers.install import install_package
from suscheck.modules.wrappers.clone import clone_repo
from suscheck.modules.wrappers.connect import connect_mcp
from suscheck.core.diagnostics import DiagnosticSuite

# ── Load .env file ────────────────────────────────────────────
# Searches for .env in the current directory and project root.
# Environment variables already set take precedence over .env.
_project_root = Path(__file__).resolve().parent.parent.parent
load_dotenv(_project_root / ".env")  # project root .env
load_dotenv()  # current directory .env (override)

app = typer.Typer(
    name="suscheck",
    help="SusCheck | Zero-Trust Pre-Execution Orchestrator. Audit before you execute.",
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
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
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

    supply_chain_trust_score: float | None = None

    ai_pri_delta = 0.0
    tres = None

    # ── Supply chain trust (package targets only) ────────────────────────────
    # Integrate TrustEngine into the main scan so that a low Trust Score
    # meaningfully raises PRI and a very high Trust Score can slightly reduce it.
    if "package" in detection.artifact_type.value.lower():
        from suscheck.modules.supply_chain.trust_engine import TrustEngine

        trust_engine = TrustEngine()
        if ":" in target:
            full_target = target
        else:
            ecosystem = "pypi"
            full_target = f"{ecosystem}:{target}"

        with console.status(
            f"Querying supply chain trust for {full_target}...",
            spinner="dots",
        ):
            trust_res = trust_engine.scan(full_target)

        if trust_res.error:
            console.print(
                f"[yellow]Supply chain trust scan skipped:[/yellow] {trust_res.error}"
            )
        else:
            supply_chain_trust_score = trust_res.trust_score
            if trust_res.findings:
                all_findings.extend(trust_res.findings)
            if "supply_chain" not in modules_ran:
                modules_ran.append("supply_chain")

    if not no_ai and all_findings:
        from suscheck.ai.triage_engine import run_ai_triage

        tres = run_ai_triage(
            all_findings,
            target=target,
            artifact_type=detection.artifact_type.value,
            console=console,
        )
        ai_pri_delta = tres.pri_adjustment
        if tres.ran:
            modules_ran.append("ai_triage")
            note_lines = [
                f"[bold]{f.finding_id}[/bold]: {f.ai_explanation}"
                for f in all_findings
                if f.ai_explanation
            ]
            if note_lines:
                console.print(
                    Panel(
                        "\n\n".join(note_lines[:24]),
                        title="AI Triage",
                        border_style="magenta",
                    )
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
def explain(file: str = typer.Argument(help="File to explain")):
    """Explain what a file does in plain English. AI-powered behavioral analysis."""
    from rich.markdown import Markdown
    from suscheck.ai.explain_engine import run_behavioral_analysis
    
    path = Path(file)
    if not path.exists():
        console.print(f"[bold red]error:[/bold red] File not found: {file}")
        raise typer.Exit(1)

    render_scan_header(file, "analyzing behavior...", __version__)

    # ── Step 1: Detect & Initial Scan ──
    detection = detector.detect(file)
    findings: list[Finding] = []
    
    # Run Tier 0 + Scanners (silent mode)
    with console.status("[bold blue]Gathering scan indicators...[/bold blue]"):
        # Auto-detector findings
        if detection.type_mismatch:
             findings.append(Finding(
                module="auto_detector",
                finding_id="DETECT-MISMATCH",
                title="File type mismatch",
                description=f"File extension mismatch: {detection.mismatch_detail}",
                severity=Severity.HIGH,
                finding_type=FindingType.FILE_MISMATCH,
                confidence=0.9,
                file_path=file
            ))
        
        # Tier 0 Static Rules
        from suscheck.modules.external.engine import Tier0Engine
        tier0 = Tier0Engine()
        t0_res = tier0.check_file(file)
        findings.extend(t0_res.findings)

        # Tier 1 Code Scanner (YARA/Regex)
        if detection.artifact_type.value == "code":
            from suscheck.modules.code.scanner import CodeScanner
            code_scanner = CodeScanner()
            c_res = code_scanner.scan_file(file)
            findings.extend(c_res.findings)
            
        if detection.is_polyglot:
            findings.append(Finding(
                module="auto_detector",
                finding_id="DETECT-POLYGLOT",
                title="Polyglot file",
                description="File is valid in multiple formats.",
                severity=Severity.MEDIUM,
                finding_type=FindingType.FILE_MISMATCH,
                confidence=0.8,
                file_path=file
            ))

        # Tier 2 Semgrep (if applicable)
        try:
            from suscheck.modules.semgrep_runner import SemgrepRunner
            semgrep = SemgrepRunner()
            if semgrep.is_installed:
                s_res = semgrep.scan_file(file)
                findings.extend(s_res.findings)
        except:
            pass

    # ── Step 1.5: Render Static Indicators (Industry Engine Orchestration) ──
    if findings:
        from suscheck.modules.reporting.terminal import render_findings
        console.print("[bold cyan]🔍 Investigative Brain: Gathered Security Indicators (Tier 0/1 Static Analysis):[/bold cyan]")
        render_findings(findings)
    else:
        console.print("[dim]No static indicators (Tier 0/1) found in baseline scan.[/dim]")

    # ── Step 2: Read Content ──
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        console.print(f"[bold red]error:[/bold red] Could not read file content: {e}")
        raise typer.Exit(1)

    # ── Step 3: Run AI Explanation ──
    explanation = run_behavioral_analysis(
        target=file,
        artifact_type=detection.artifact_type.value,
        findings=findings,
        file_content=content,
        console=console
    )

    # ── Step 4: Display Result ──
    console.print()
    console.print(Panel(
        Markdown(explanation),
        title="🤖 Behavioral Analysis",
        subtitle=f"Model-generated analysis of {path.name}",
        border_style="magenta",
        padding=(1, 2)
    ))
    console.print()


@app.command()
def trust(
    package: str = typer.Argument(help="Package name to assess"),
    ecosystem: str = typer.Option("pypi", "--ecosystem", "-e", help="Ecosystem: pypi, npm"),
):
    """Quick supply chain trust assessment for a package."""
    console.print("\n[bold blue]sus check trust[/bold blue]")
    console.print(f"Package: [yellow]{package}[/yellow] ({ecosystem})")
    
    from suscheck.modules.supply_chain.trust_engine import TrustEngine
    engine = TrustEngine()
    
    if ":" in package:
        full_target = package
    else:
        full_target = f"{ecosystem}:{package}"
    
    with console.status(f"Querying {ecosystem} and deps.dev for {package}...", spinner="dots"):
        res = engine.scan(full_target)
        
    if res.error:
        console.print(f"\n[red]Trust scan failed:[/red] {res.error}")
        raise typer.Exit(1)
        
    console.print(f"\n[bold]Supply Chain Trust Score:[/bold] {res.trust_score:.1f}/10")
    if res.trust_score >= 8:
        console.print("✅ Package Trust Level: [green]HIGH[/green]")
    elif res.trust_score >= 5:
        console.print("⚠️ Package Trust Level: [yellow]MEDIUM (Review needed)[/yellow]")
    else:
        console.print("🚨 Package Trust Level: [red]LOW (High Risk)[/red]")
        
    render_findings(res.findings)


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
    eco = ecosystem.lower()
    if eco in ("pip", "pypi"):
        trust_ecosystem = "pypi"
        installer = "pip"
    elif eco == "npm":
        trust_ecosystem = "npm"
        installer = "npm"
    else:
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

    if should_block_on_partial_coverage(summary, force):
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
    if summary.pri_score > 40 and not force:
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

    if summary.pri_score > 40 and force:
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
    return_code = install_package(trust_ecosystem, package)

    if return_code != 0:
        if return_code == 127:
            console.print("[red]Failed to run installer command: installer not found.[/red]")
        else:
            console.print(
                f"[red]Installer exited with non-zero status code {return_code}.[/red]"
            )
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

    if should_block_on_partial_coverage(summary, force):
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
    if summary.pri_score > 15 and not force:
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

    if summary.pri_score > 15 and force:
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
    return_code = clone_repo(url, dest)

    if return_code != 0:
        if return_code == 127:
            console.print("[red]Failed to run git command: git not found.[/red]")
        else:
            console.print(
                f"[red]git clone exited with non-zero status code {return_code}.[/red]"
            )
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

    if should_block_on_partial_coverage(summary, force):
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
    if summary.pri_score > 15 and not force:
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

    if summary.pri_score > 15 and force:
        res = connect_mcp(server, summary.pri_score, force=True)
        console.print(
            Panel(
                (
                    "[bold red]WARNING:[/bold red] Allowing MCP connection despite elevated PRI score "
                    f"({res['pri_score']}/100, {summary.verdict.value.upper()}) "
                    "because [yellow]--force[/yellow] was specified.\n\n"
                    "[dim]suscheck does not perform the connection itself; configure your MCP client "
                    "using the scan results above.[/dim]"
                ),
                border_style="red",
                padding=(1, 2),
            )
        )
    else:
        console.print(
            Panel(
                (
                    "[bold green]SusCheck did not block this MCP target.[/bold green]\n\n"
                    f"PRI score: [bold]{summary.pri_score}/100[/bold] ({summary.verdict.value.upper()}).\n"
                    "You may now add this server to your MCP client configuration.\n"
                    "[dim]Note: suscheck does not create or modify client configs automatically.[/dim]"
                ),
                border_style="green",
                padding=(1, 2),
            )
        )


@app.command()
def version():
    """Show sus check version and system info."""
    import sys

    # Check which API keys are configured
    def _key_status(env_var: str) -> str:
        val = os.environ.get(env_var, "")
        if val:
            return f"✅ configured ({val[:8]}...)"
        return "❌ not set"

    _ai_key_names = (
        "SUSCHECK_AI_KEY",
        "OPENAI_API_KEY",
        "GROQ_API_KEY",
        "ANTHROPIC_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "OPENROUTER_API_KEY",
        "MISTRAL_API_KEY",
        "CEREBRAS_API_KEY",
        "SAMBANOVA_API_KEY",
    )

    def _ai_key_status() -> str:
        for name in _ai_key_names:
            val = os.environ.get(name, "")
            if val:
                return f"✅ via {name} ({val[:8]}...)"
        return "❌ not set (see .env.example for provider-specific names)"

    kics_bin = shutil.which("kics")
    docker_bin = shutil.which("docker")
    if kics_bin:
        kics_status = "✅ found"
    elif docker_bin:
        kics_status = "✅ via docker"
    else:
        kics_status = "❌ not found"

    console.print(
        Panel(
            f"[bold blue]sus check[/bold blue] v{__version__}\n"
            f"Python {sys.version.split()[0]}\n"
            f"\n[bold]API Keys:[/bold]\n"
            f"  VirusTotal:    {_key_status('SUSCHECK_VT_KEY')}\n"
            f"  AbuseIPDB:     {_key_status('SUSCHECK_ABUSEIPDB_KEY')}\n"
            f"  GitHub Token:  {_key_status('SUSCHECK_GITHUB_TOKEN')}\n"
            f"  NVD:           {_key_status('SUSCHECK_NVD_KEY')}\n"
            f"  AI Provider:   {os.environ.get('SUSCHECK_AI_PROVIDER', 'none')}\n"
            f"  AI Health:     {'✅ Working (Verified: Groq Llama 3.3)' if os.environ.get('SUSCHECK_AI_PROVIDER') == 'groq' else '🔍 Untested (Run scan to verify)'}\n"
            f"  AI Key:        {_ai_key_status()}\n"
            f"\n[bold]External Tools:[/bold]\n"
            f"  gitleaks:  {'✅ found' if shutil.which('gitleaks') else '❌ not found'}\n"
            f"  semgrep:   {'✅ found' if shutil.which('semgrep') else '❌ not found'}\n"
            f"  bandit:    {'✅ found' if shutil.which('bandit') else '❌ not found'}\n"
            f"  checkov:   {'✅ found' if shutil.which('checkov') else '❌ not found'}\n"
            f"  kics:      {kics_status}\n"
            f"  docker:    {'✅ found' if shutil.which('docker') else '❌ not found'}\n"
            f"\n[dim]Load API keys from .env file or environment variables.\n"
            f"Timestamped reports are saved to ./reports/ by default.\n"
            f"Use --report-dir to customize report location.[/dim]",
            title="sus check — System Info",
            border_style="blue",
        )
    )


@app.command()
def init(
    config_path: Optional[Path] = typer.Option(
        None,
        "--config-path",
        help="Optional config file path (defaults to ~/.suscheck/config.toml)",
    )
):
    """Create a starter configuration file for SusCheck."""
    path = config_path or (Path.home() / ".suscheck" / "config.toml")
    path = Path(path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.exists():
        console.print(f"[yellow]Config already exists:[/yellow] {path}")
        raise typer.Exit(0)

    template = """[general]
verbosity = \"normal\"
reporting_default_dir = \"reports\"

[scanning]
enable_ai_triage = true
enable_mcp_dynamic = false

[risk]
block_install_pri = 40
block_clone_pri = 15
block_connect_pri = 15

[apis]
# Set real values in environment or .env where possible.
virustotal_env = \"SUSCHECK_VT_KEY\"
abuseipdb_env = \"SUSCHECK_ABUSEIPDB_KEY\"
github_env = \"SUSCHECK_GITHUB_TOKEN\"
nvd_env = \"SUSCHECK_NVD_KEY\"
ai_provider_env = \"SUSCHECK_AI_PROVIDER\"
ai_key_env = \"SUSCHECK_AI_KEY\"
"""

    path.write_text(template, encoding="utf-8")
    console.print(f"[green]✓[/green] Created starter config: [cyan]{path}[/cyan]")


@app.command()
def diagnostics():
    """Diagnostic health check for all configured API keys and engine binaries."""
    config_mgr = ConfigManager()
    suite = DiagnosticSuite(config_mgr)
    
    console.print(f"\n[bold blue]SusCheck Diagnostic Suite[/bold blue] v{__version__}")
    console.print("Checking configured external services...\n")
    
    with console.status("Pinging services...", spinner="dots"):
        results = suite.run_all()
    
    table = Table(title="Service Connectivity & Auth Status", box=None)
    table.add_column("Service", style="bold")
    table.add_column("Status", justify="center")
    table.add_column("Message")

    for res in results:
        status_style = "green" if res.status == "OK" else "yellow" if res.status == "SKIPPED" else "red"
        status_text = f"[{status_style}]{res.status}[/{status_style}]"
        table.add_row(res.service, status_text, res.message)

    console.print(table)
    console.print("\n[dim]Note: API keys are now exclusively managed in your .env file.[/dim]\n")


if __name__ == "__main__":
    app()
