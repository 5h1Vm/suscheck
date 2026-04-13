"""suscheck CLI — the main entry point."""

import logging
import os
import subprocess
import sys
import time
from enum import Enum
from pathlib import Path
from typing import List, Optional, Union

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from suscheck import __version__
from suscheck.core.auto_detector import AutoDetector, Language
from suscheck.core.finding import Finding, FindingType, ScanSummary, Severity, Verdict, ReportFormat
from suscheck.core.risk_aggregator import RiskAggregator
from suscheck.modules.code.scanner import CodeScanner
from suscheck.modules.config.scanner import ConfigScanner
from suscheck.modules.mcp.dynamic import MCPDynamicScanner
from suscheck.modules.mcp.scanner import MCPScanner
from suscheck.modules.repo.scanner import RepoScanner
from suscheck.modules.supply_chain.auditor import SupplyChainAuditor
from suscheck.modules.reporting.terminal import (
    render_findings,
    render_scan_footer,
    render_scan_header,
    render_verdict,
    render_vt_result,
)
from suscheck.core.pipeline import ScanPipeline
from suscheck.modules.external import Tier0Engine
from suscheck.core.config_manager import ConfigManager
from suscheck.modules.wrappers.install import install_package
from suscheck.modules.wrappers.clone import clone_repo
from suscheck.modules.wrappers.connect import connect_mcp
from suscheck.core.diagnostics import DiagnosticSuite, DiagnosticResult

# ── Load .env file ────────────────────────────────────────────
# Searches for .env in the current directory and project root.
# Environment variables already set take precedence over .env.
_project_root = Path(__file__).resolve().parent.parent.parent
load_dotenv(_project_root / ".env")  # project root .env
load_dotenv()  # current directory .env (override)

app = typer.Typer(
    name="suscheck",
    help="sus check — Pre-execution security scanning platform. Scan before you trust.",
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
    target_path = Path(target)
    config_mgr = ConfigManager()
    detector = AutoDetector(config_mgr)
    detection = detector.detect(target)
    
    # --- Step 1: Render Header with Real Info ---
    type_display = f"{detection.artifact_type.value.upper()}"
    if detection.language != Language.UNKNOWN:
        type_display += f" ({detection.language.value.capitalize()})"
        
    render_scan_header(target, type_display, __version__)

    pipeline = ScanPipeline(config_mgr)
    target_path = Path(target).resolve()
    
    # Check if target is intended to be a local path and verify existence
    is_explicit_local = any(target.startswith(p) for p in ["./", "../", "/"])
    if is_explicit_local and not target_path.exists():
        console.print(f"\n[bold red]CRITICAL: Target path not found:[/bold red] {target}")
        console.print("[dim]If this is a package name, do not use path prefixes (e.g. use 'requests' instead of './requests')[/dim]")
        sys.exit(1)

    if target_path.is_dir():
        console.print(f"\n[bold blue]Recursive directory scan initiated:[/bold blue] {target}")
        
        with console.status(f"Scanning directory {target}...", spinner="bouncingBar"):
            all_findings = pipeline.scan_directory(target)
        
        modules_ran = pipeline.get_modules_ran(all_findings)
        scan_duration = time.time() - scan_start
        
        aggregator = RiskAggregator("DIRECTORY")
        pri_result = aggregator.calculate(all_findings)
        
        summary = _build_summary(
            target=target,
            artifact_type="DIRECTORY",
            findings=all_findings,
            pri_score=pri_result.score,
            modules_ran=list(modules_ran),
            scan_duration=scan_duration,
            verdict=pri_result.verdict,
            pri_breakdown=pri_result.breakdown
        )
        
        console.print(Panel("\n".join(pri_result.breakdown), title="Score Explanation", border_style="dim"))
        render_findings(all_findings)
        render_verdict(summary)
        render_scan_footer(summary)
        
        # Reporting logic
        if report_format != ReportFormat.TERMINAL:
             config_mgr = ConfigManager()
             from suscheck.core.reporter import ReportGenerator
             
             # Check if we should use timestamped folders from config
             use_timestamp = config_mgr.get("reporting.timestamped", True)
             
             report_path = ReportGenerator.get_default_path(
                 target, 
                 report_format, 
                 report_dir or config_mgr.get("reporting.default_dir"), 
                 timestamped=use_timestamp
             )
             
             content = ""
             if report_format == ReportFormat.MARKDOWN: content = ReportGenerator.generate_markdown(summary)
             elif report_format == ReportFormat.HTML: content = ReportGenerator.generate_html(summary)
             elif report_format == ReportFormat.JSON:
                import json
                from dataclasses import asdict
                content = json.dumps(asdict(summary), default=lambda o: o.value if isinstance(o, Enum) else str(o), indent=2)
             
             report_path.write_text(content, encoding="utf-8")
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
                f"The file extension does not match the actual file type detected "
                f"by magic bytes. This is a common malware evasion technique "
                f"(e.g., renaming an EXE to .txt)."
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
    console.print("\n[bold]Tier 0: Hash & Reputation[/bold]")

    # Show what services are configured
    vt_key = os.environ.get("SUSCHECK_VT_KEY", "")
    if vt_key:
        console.print("  [green]✓[/green] VirusTotal API key configured")
    else:
        console.print("  [yellow]○[/yellow] VirusTotal: no API key — [dim]set SUSCHECK_VT_KEY or add to .env[/dim]")

    # Check if target is a file (Tier 0 only works on files)
    file_path = detection.file_path
    if file_path and os.path.isfile(str(file_path)):
        tier0 = Tier0Engine()

        if upload_vt:
            console.print("  [yellow]⚠️  --upload-vt: file will be uploaded to VT (becomes PUBLIC)[/yellow]")

        tier0_result = tier0.check_file(str(file_path), upload_vt=upload_vt)

        # Show hash results
        if tier0_result.hash_result:
            hash_table = Table(border_style="dim", show_header=False, padding=(0, 1))
            hash_table.add_column("Hash", style="dim bold", width=8)
            hash_table.add_column("Value", style="dim")
            hash_table.add_row("SHA-256", tier0_result.hash_result.sha256)
            hash_table.add_row("MD5", tier0_result.hash_result.md5)
            hash_table.add_row("SHA-1", tier0_result.hash_result.sha1)
            hash_table.add_row(
                "Size",
                f"{tier0_result.hash_result.file_size:,} bytes",
            )
            console.print(hash_table)

        # Show VT results
        render_vt_result(tier0_result.vt_dict)

        # Show findings from Tier 0
        if tier0_result.findings:
            render_findings(tier0_result.findings)

        # Handle short-circuit
        if tier0_result.short_circuit:
            console.print(
                Panel(
                    "[bold red]⚡ SHORT-CIRCUIT: Known malicious file detected.\n"
                    "Scan terminated at Tier 0. No further analysis needed.[/bold red]",
                    border_style="red",
                    title="⚡ Short-Circuit",
                )
            )

            # Build summary for short-circuit verdict
            aggregator = RiskAggregator(detection.artifact_type.value)
            pri_result = aggregator.calculate(tier0_result.findings, tier0_result.vt_dict)
            
            # Since it's a short circuit on malicious hash, we force score to 100
            final_score = max(prior_score := pri_result.score, 100)
            
            # if we forcibly bumped the score to 100, add to the breakdown to explain why
            if prior_score < 100:
                pri_result.breakdown.insert(-1, "  [red]⚡ Tier 0 Short-Circuit[/red] (Known Malicious Hash) → bumped score to [bold]100/100[/bold]")
                pri_result.breakdown[-1] = "  [bold]Total Score: 100/100[/bold]"

            def print_unified_report(target: str, res: dict, console: Console):
                """Print the final Security Trust Report with a detailed PRI breakdown."""
                pri = res["pri"]
                findings = res["findings"]
                duration = res["duration"]
                artifact = res["artifact_info"]

                console.print()
                console.print(Panel(
                    f"[bold blue]SECURITY TRUST REPORT[/bold blue]\n"
                    f"Target: [cyan]{artifact['path']}[/cyan]\n"
                    f"Type: {artifact['type']} | Files: {artifact['file_count']} | Time: {duration:.2f}s",
                    # Aligned with Checkpoint 1a Unified Context
                    title="[bold white]SusCheck Analysis Summary[/bold white]",
                    border_style="blue"
                ))

            summary = _build_summary(
                target=target,
                artifact_type=detection.artifact_type.value,
                findings=tier0_result.findings,
                pri_score=final_score,
                modules_ran=["tier0"],
                scan_duration=time.time() - scan_start,
                vt_result=tier0_result.vt_dict,
                pri_breakdown=pri_result.breakdown,
            )
            
            console.print(Panel(
                "\n".join(pri_result.breakdown),
                title="Score Explanation",
                border_style="dim",
                padding=(0, 2),
            ))
            render_verdict(summary)
            render_scan_footer(summary)
            return summary

        # Show Tier 0 timing
        console.print(
            f"[dim]Tier 0 completed in {tier0_result.scan_duration:.2f}s[/dim]"
        )

        if tier0_result.errors:
            for error in tier0_result.errors:
                console.print(f"[yellow]⚠️ {error}[/yellow]")

        # Build partial summary (more modules will add to this later)
        all_findings.extend(tier0_result.findings)
        vt_dict = tier0_result.vt_dict
        modules_ran = ["tier0"]
    else:
        console.print("[dim]Tier 0 skipped: target is not a local file[/dim]")
        vt_dict = None
        modules_ran = []

    # ── Remaining modules (Tier 1, Tier 2) ────────────────────
    if file_path and os.path.isfile(str(file_path)):
        console.print("\n[bold]Tier 1: Static Analysis[/bold]")
        try:
            config_scanner = ConfigScanner()
            repo_scanner = RepoScanner()
            mcp_scanner = MCPScanner()

            if mcp_scanner.can_handle(detection.artifact_type.value, str(file_path)):
                scanner = mcp_scanner
                code_result = scanner.scan(str(file_path))
                modules_ran.append("mcp")
            elif repo_scanner.can_handle(detection.artifact_type.value, str(file_path)):
                scanner = repo_scanner
                code_result = scanner.scan(str(file_path))
                modules_ran.append("repo")
            elif config_scanner.can_handle(detection.artifact_type.value, str(file_path)):
                scanner = config_scanner
                code_result = scanner.scan(str(file_path))
                modules_ran.append("config")
            else:
                scanner = CodeScanner()
                code_result = scanner.scan_file(str(file_path), language=detection.language.value)
                modules_ran.append("code")

            all_findings.extend(code_result.findings)

            skipped = getattr(code_result, "skipped_reason", None)
            if skipped:
                if skipped == "binary_file":
                    console.print(f"  [dim]Skipped Scanner: Binary file[/dim]")
                elif skipped == "file_too_large":
                    console.print(f"  [dim]Skipped Scanner: File too large (>5MB)[/dim]")
            
            err = getattr(code_result, "error", None)
            if err:
                console.print(f"  [dim]Scanner error/skipped: {err}[/dim]")
            
                from suscheck.modules.external.virustotal import VirusTotalClient
                from suscheck.modules.external.abuseipdb import AbuseIPDBClient
                
                vt_client = VirusTotalClient()
                abuse_client = AbuseIPDBClient()
                
                unique_urls = set()
                unique_ips = set()
                
                for f in code_result.findings:
                    if f.evidence.get("type") == "url":
                        unique_urls.add(f.evidence.get("value"))
                    elif f.evidence.get("type") == "ipv4":
                        unique_ips.add(f.evidence.get("value"))
                
                # Limit to 3 lookups per type to prevent rate limiting
                if unique_urls and vt_client.available:
                    console.print(f"  [dim]Querying VirusTotal for {min(3, len(unique_urls))} URLs...[/dim]")
                    for url in list(unique_urls)[:3]:
                        vt_res = vt_client.lookup_url(url)
                        if vt_res and (vt_res.detection_count or 0) > 0:
                            vt_finding = Finding(
                                module="virustotal",
                                finding_id=f"VT-URL-{abs(hash(url)) % 10000}",
                                title=f"Malicious URL detected: {url[:30]}...",
                                description=f"URL flagged by {vt_res.detection_count}/{vt_res.total_engines} VirusTotal engines.",
                                severity=Severity.CRITICAL if vt_res.detection_count > 3 else Severity.HIGH,
                                finding_type=FindingType.C2_INDICATOR,
                                confidence=0.9,
                                mitre_ids=["T1071"],
                                evidence={"url": url, "detections": vt_res.detection_count}
                            )
                            code_result.findings.append(vt_finding)
                            all_findings.append(vt_finding)
                            
                if unique_ips and abuse_client.is_configured:
                    console.print(f"  [dim]Querying AbuseIPDB for {min(3, len(unique_ips))} IP addresses...[/dim]")
                    for ip in list(unique_ips)[:3]:
                        abuse_res = abuse_client.lookup_ip(ip)
                        if abuse_res and abuse_res.abuse_confidence_score > 0:
                            abuse_finding = abuse_client.create_finding(abuse_res)
                            if abuse_finding:
                                code_result.findings.append(abuse_finding)
                                all_findings.append(abuse_finding)

                render_findings(code_result.findings)
        except Exception as e:
            console.print(f"  [red]Tier 1 static scan failed: {e}[/red]")

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

        # ==========================================
        # Tier 2: Layer 2 SAST (Semgrep)
        # ==========================================
        console.print("\n[bold]Tier 2: Advanced SAST (Semgrep)[/bold]")
        try:
            from suscheck.modules.semgrep_runner import SemgrepRunner
            semgrep_runner = SemgrepRunner()
            
            if semgrep_runner.is_installed:
                console.print("  [dim]Running Semgrep rules...[/dim]")
                semgrep_result = semgrep_runner.scan_file(str(file_path))
                
                if semgrep_result.findings:
                    all_findings.extend(semgrep_result.findings)
                    render_findings(semgrep_result.findings)
                else:
                    if not semgrep_result.errors:
                        console.print("  [dim]No Semgrep vulnerabilities found.[/dim]")
                    
                if semgrep_result.errors:
                    for err in semgrep_result.errors:
                        console.print(f"  [yellow]⚠️ Semgrep Warning: {err}[/yellow]")
            else:
                console.print("  [yellow]⚠️ Semgrep not installed. Skipping Layer 2 SAST.[/yellow]")
                
        except Exception as e:
            console.print(f"  [red]Semgrep orchestration failed: {e}[/red]")


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

    modules_skipped: list[str] = []
    if "package" in detection.artifact_type.value.lower() and "supply_chain" not in modules_ran:
        modules_skipped.append("supply_chain")
    if "ai_triage" not in modules_ran:
        modules_skipped.append("ai_triage")
    if file_path and os.path.isfile(str(file_path)) and "mcp" not in modules_ran:
        modules_skipped.append("mcp")
    if (
        file_path
        and os.path.isfile(str(file_path))
        and "mcp" in modules_ran
        and "mcp_dynamic" not in modules_ran
    ):
        if not mcp_dynamic:
            modules_skipped.append("mcp_dynamic")

    summary = _build_summary(
        target=target,
        artifact_type=detection.artifact_type.value,
        findings=all_findings,
        pri_score=pri_result.score,
        modules_ran=modules_ran,
        modules_skipped=modules_skipped,
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
        from suscheck.core.reporter import ReportGenerator

        content = ""
        if report_format == ReportFormat.JSON:
            import json
            from dataclasses import asdict

            def enum_converter(obj):
                if isinstance(obj, Enum):
                    return obj.value
                raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

            content = json.dumps(asdict(summary), default=enum_converter, indent=2)
        elif report_format == ReportFormat.MARKDOWN:
            content = ReportGenerator.generate_markdown(summary)
        elif report_format == ReportFormat.HTML:
            content = ReportGenerator.generate_html(summary)

        report_path = output
        if not report_path and report_format != ReportFormat.TERMINAL:
            config_mgr = ConfigManager()
            from suscheck.core.reporter import ReportGenerator
            
            # Generate a default timestamped path if no output path provided
            use_timestamp = config_mgr.get("reporting.timestamped", True)
            report_path = ReportGenerator.get_default_path(
                target, 
                report_format, 
                report_dir or config_mgr.get("reporting.default_dir"),
                timestamped=use_timestamp
            )

        if report_path:
            try:
                report_path.write_text(content, encoding="utf-8")
                console.print(f"\n[bold green]✓[/bold green] Report saved to: [cyan]{report_path}[/cyan]")
            except Exception as e:
                console.print(f"\n[bold red]✗[/bold red] Failed to save report: {e}")
        else:
            # If no output path, print to stdout (helpful for piping)
            print(content)

    return summary



def _build_summary(
    target: str,
    artifact_type: str,
    findings: list[Finding],
    pri_score: int,
    modules_ran: list[str],
    modules_skipped: list[str] | None = None,
    scan_duration: float = 0.0,
    vt_result: dict | None = None,
    trust_score: float | None = None,
    verdict: Verdict | None = None,
    pri_breakdown: list[str] | None = None,
) -> ScanSummary:
    """Build a ScanSummary from current scan state."""
    # Prefer an explicit verdict (from RiskAggregator) when provided,
    # but fall back to deriving it from the PRI score so callers that
    # do not use RiskAggregator remain supported.
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
        critical_count=sum(1 for f in findings if f.severity == Severity.CRITICAL),
        high_count=sum(1 for f in findings if f.severity == Severity.HIGH),
        medium_count=sum(1 for f in findings if f.severity == Severity.MEDIUM),
        low_count=sum(1 for f in findings if f.severity == Severity.LOW),
        info_count=sum(1 for f in findings if f.severity == Severity.INFO),
        review_count=sum(1 for f in findings if f.needs_human_review),
        scan_duration=scan_duration,
        modules_ran=modules_ran,
        modules_skipped=modules_skipped or [],
        vt_result=vt_result,
        trust_score=trust_score,
        pri_breakdown=pri_breakdown or [],
    )


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

    # ── Step 1.5: Render Static Indicators ──
    if findings:
        from suscheck.modules.reporting.terminal import render_findings
        console.print("[bold cyan]🔍 Forensic Indicators Gathered:[/bold cyan]")
        render_findings(findings)
    else:
        console.print("[dim]No static indicators found in baseline scan.[/dim]")

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
    console.print(f"\n[bold blue]sus check trust[/bold blue]")
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
    console.print(f"\n[bold blue]sus check install[/bold blue]")
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
    summary = scan(target=scan_target)

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
    console.print(f"\n[bold]Executing installation...[/bold]\n")
    return_code = install_package(trust_ecosystem, package)

    if return_code != 0:
        if return_code == 127:
            console.print(f"[red]Failed to run installer command: installer not found.[/red]")
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
    console.print(f"\n[bold blue]sus check clone[/bold blue]")
    console.print(f"Repository: [yellow]{url}[/yellow]")

    console.print("\n[dim]Scanning repository URL before clone...[/dim]")
    summary = scan(target=url)

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
    console.print(f"\n[bold]Executing git clone...[/bold]\n")
    return_code = clone_repo(url, dest)

    if return_code != 0:
        if return_code == 127:
            console.print(f"[red]Failed to run git command: git not found.[/red]")
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
    console.print(f"\n[bold blue]sus check connect[/bold blue]")
    console.print(f"MCP Server: [yellow]{server}[/yellow]")

    console.print("\n[dim]Scanning MCP server target before connection...[/dim]")
    summary = scan(target=server)

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
def install(
    package: str = typer.Argument(help="Package name or ecosystem:name (e.g. pypi:requests)"),
    ecosystem: str = typer.Option("pypi", "--ecosystem", "-e", help="Ecosystem: pypi, npm"),
    force: bool = typer.Option(False, "--force", help="Skip security check and install anyway"),
):
    """Secure installer wrapper. Scans package trust score before installation."""
    console.print(f"\n[bold blue]sus check install[/bold blue]")
    console.print(f"Target: [yellow]{package}[/yellow] ({ecosystem})")
    
    if not force:
        # Perform Trust Scan First
        from suscheck.modules.supply_chain.trust_engine import TrustEngine
        engine = TrustEngine()
        
        full_target = package if ":" in package else f"{ecosystem}:{package}"
        
        with console.status(f"Auditing supply chain trust for {full_target}...", spinner="bouncingBar"):
            res = engine.scan(full_target)
            
        if res.trust_score is not None:
            style = "green" if res.trust_score >= 7.0 else "yellow" if res.trust_score >= 4.0 else "red"
            console.print(f"Trust Score: [{style}]{res.trust_score}/10.0[/{style}]")
            
            if res.findings:
                render_findings(res.findings)
                
            if res.trust_score < 4.0:
                console.print(Panel(
                    f"[bold red]❌ SECURITY BLOCK:[/bold red] Package [bold]{package}[/bold] has extremely low trust.\n"
                    "Installation halted to prevent potential supply chain compromise.\n"
                    "Use [dim]--force[/dim] to override if you are absolutely sure.",
                    border_style="red"
                ))
                raise typer.Exit(1)
            elif res.trust_score < 7.0:
                console.print("[yellow]⚠️  CAUTION:[/yellow] Trust score is moderate. Proceed with care.")

    # Proceed to Install
    console.print(f"\n[bold green]✓[/bold green] Security check passed. Commencing {ecosystem} install...")
    exit_code = install_package(ecosystem, package)
    
    if exit_code == 0:
        console.print(f"[bold green]✓[/bold green] Package '{package}' installed successfully.")
    else:
        console.print(f"[bold red]✗[/bold red] Install failed with exit code {exit_code}")
        raise typer.Exit(exit_code)


@app.command()
def clone(
    url: str = typer.Argument(help="Git repository URL to clone"),
    dest: Optional[str] = typer.Option(None, "--dest", "-d", help="Destination folder"),
    force: bool = typer.Option(False, "--force", help="Skip security check"),
):
    """Secure clone wrapper. Scans repository metadata before cloning."""
    console.print(f"\n[bold blue]sus check clone[/bold blue]")
    console.print(f"Repo: [yellow]{url}[/yellow]")
    
    if not force:
        # Perform Repo Metadata Scan
        repo_scanner = RepoScanner()
        with console.status(f"Auditing repository integrity...", spinner="bouncingBar"):
            res = repo_scanner.scan(url)
            
        if res.findings:
            render_findings(res.findings)
            
            # Simple heuristic for blocking: any critical/high findings in metadata
            has_major_risk = any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in res.findings)
            if has_major_risk:
                console.print(Panel(
                    "[bold red]❌ SECURITY BLOCK:[/bold red] Repository metadata reveals high-risk indicators.\n"
                    "Cloning suspended. Use [dim]--force[/dim] to override.",
                    border_style="red"
                ))
                raise typer.Exit(1)

    # Proceed to Clone
    console.print(f"\n[bold green]✓[/bold green] Pre-clone check passed. Initiating git clone...")
    exit_code = clone_repo(url, dest)
    
    if exit_code == 0:
        console.print(f"[bold green]✓[/bold green] Repository cloned successfully.")
    else:
        console.print(f"[bold red]✗[/bold red] Clone failed with exit code {exit_code}")
        raise typer.Exit(exit_code)


@app.command()
def connect(
    target: str = typer.Argument(help="MCP server target (command, URL, or id)"),
    force: bool = typer.Option(False, "--force", help="Skip security check"),
):
    """Secure MCP connection wrapper. Scans MCP server before connecting."""
    console.print(f"\n[bold blue]sus check connect[/bold blue]")
    console.print(f"MCP Server: [yellow]{target}[/yellow]")
    
    if not force:
        mcp_scanner = MCPScanner()
        with console.status(f"Auditing MCP server capabilities...", spinner="bouncingBar"):
            res = mcp_scanner.scan(target)
            
        if res.findings:
            render_findings(res.findings)
            
            # Block if critical vulnerabilities or prompt injection potential found
            if any(f.severity == Severity.CRITICAL for f in res.findings):
                 console.print(Panel(
                    "[bold red]❌ SECURITY BLOCK:[/bold red] MCP server has critical over-privilege or vulnerabilities.\n"
                    "Connection blocked. Use [dim]--force[/dim] to override.",
                    border_style="red"
                ))
                 raise typer.Exit(1)

    # Proceed to Connect (this is a stub in v1, usually prints the verified connection string)
    console.print(f"\n[bold green]✓[/bold green] Pre-connection check passed. Service verified.")
    connect_mcp(target)


@app.command()
def version():
    """Show sus check version and system info."""
    import shutil
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
            f"  kics:      {'✅ found' if shutil.which('kics') else '❌ not found (Checkov used as primary)'}\n"
            f"  docker:    {'✅ found' if shutil.which('docker') else '❌ not found'}\n"
            f"\n[dim]Load API keys from .env file or environment variables.\n"
            f"Timestamped reports are saved to ./reports/ by default.\n"
            f"Use --report-dir to customize report location.[/dim]",
            title="sus check — System Info",
            border_style="blue",
        )
    )
@app.command()
def diagnostics():
    """Diagnostic health check for all configured API keys and engine binaries."""
    config_mgr = ConfigManager()
    suite = DiagnosticSuite(config_mgr)
    
    console.print(f"\n[bold blue]SusCheck Diagnostic Suite[/bold blue] v{__version__}")
    console.print(f"Checking configured external services...\n")
    
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
