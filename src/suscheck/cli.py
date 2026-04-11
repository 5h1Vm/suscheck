"""suscheck CLI — the main entry point."""

import logging
import os
import time
from pathlib import Path

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from suscheck import __version__
from suscheck.core.auto_detector import AutoDetector
from suscheck.core.finding import Finding, FindingType, ScanSummary, Severity, Verdict
from suscheck.modules.code_scanner import CodeScanner
from suscheck.output.terminal import (
    render_findings,
    render_scan_footer,
    render_scan_header,
    render_verdict,
    render_vt_result,
)
from suscheck.tier0 import Tier0Engine

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
    output: str = typer.Option("terminal", "--output", "-o", help="Output format: terminal, json"),
    report: str = typer.Option(None, "--report", "-r", help="Generate report: html, markdown"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Skip AI triage, rules-only mode"),
    upload_vt: bool = typer.Option(
        False, "--upload-vt",
        help="Upload file to VirusTotal if hash unknown. ⚠️  File becomes PUBLIC on VT.",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
):
    """Scan any artifact for security issues."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(name)s: %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING)

    scan_start = time.time()

    # ── Header ────────────────────────────────────────────────
    render_scan_header(target, "detecting...", __version__)

    # ── Step 1: Auto-detect artifact type ─────────────────────
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
            summary = _build_summary(
                target=target,
                artifact_type=detection.artifact_type.value,
                findings=tier0_result.findings,
                pri_score=min(100, 71 + tier0_result.pri_adjustment),
                modules_ran=["tier0"],
                scan_duration=time.time() - scan_start,
                vt_result=tier0_result.vt_dict,
            )
            _render_score_explanation(tier0_result.findings, summary.pri_score)
            render_verdict(summary)
            render_scan_footer(summary)
            return

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
            scanner = CodeScanner()
            code_result = scanner.scan_file(str(file_path), language=detection.language.value)
            all_findings.extend(code_result.findings)
            modules_ran.append("code")

            if code_result.skipped_reason:
                if code_result.skipped_reason == "binary_file":
                    console.print("  [dim]Skipped Code Scanner: Binary file[/dim]")
                elif code_result.skipped_reason == "file_too_large":
                    console.print("  [dim]Skipped Code Scanner: File too large (>5MB)[/dim]")
            
            # --- Dynamic Threat Intelligence Enrichment ---
            if code_result.findings:
                from suscheck.tier0.virustotal import VirusTotalClient
                from suscheck.tier0.abuseipdb import AbuseIPDBClient
                from suscheck.core.finding import Finding, FindingType, Severity
                
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
            console.print(f"  [red]Code Scanner failed: {e}[/red]")

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

    # Compute PRI score from all findings
    pri_score = _compute_preliminary_pri(all_findings)

    summary = _build_summary(
        target=target,
        artifact_type=detection.artifact_type.value,
        findings=all_findings,
        pri_score=pri_score,
        modules_ran=modules_ran,
        modules_skipped=["supply_chain", "repo", "mcp", "ai_triage"],
        scan_duration=scan_duration,
        vt_result=vt_dict,
    )
    _render_score_explanation(all_findings, summary.pri_score)
    render_verdict(summary)
    render_scan_footer(summary)


# Finding IDs that are purely informational / neutral.
# These should NOT contribute to the PRI score.
_NEUTRAL_FINDING_IDS = {
    "VT-CLEAN-001",      # VT says clean → already gets -5 PRI via pri_adjustment
    "VT-NOTFOUND-001",   # VT has no data → not a risk signal
}


def _compute_preliminary_pri(findings: list[Finding]) -> int:
    """Compute a preliminary PRI score from findings.

    This is a simplified version until the full Risk Aggregator
    is implemented. Uses base severity points × confidence.

    Neutral/informational findings (e.g., 'hash not found in VT')
    do NOT contribute to the score.
    """
    severity_points = {
        Severity.CRITICAL: 25,
        Severity.HIGH: 15,
        Severity.MEDIUM: 8,
        Severity.LOW: 3,
        Severity.INFO: 0,  # INFO findings don't contribute to PRI
    }

    score = 0.0
    for f in findings:
        if f.ai_false_positive:
            continue
        if f.finding_id in _NEUTRAL_FINDING_IDS:
            continue
        base = severity_points.get(f.severity, 0)
        score += base * f.confidence

    return min(int(score), 100)


def _render_score_explanation(findings: list[Finding], pri_score: int) -> None:
    """Render a human-readable explanation of the PRI score."""
    severity_points = {
        Severity.CRITICAL: 25,
        Severity.HIGH: 15,
        Severity.MEDIUM: 8,
        Severity.LOW: 3,
        Severity.INFO: 0,
    }

    # Skip if no findings or score is 0
    contributing = [
        f for f in findings
        if f.finding_id not in _NEUTRAL_FINDING_IDS
        and not f.ai_false_positive
        and severity_points.get(f.severity, 0) > 0
    ]
    informational = [
        f for f in findings
        if f.finding_id in _NEUTRAL_FINDING_IDS or f.severity == Severity.INFO
    ]

    lines = []

    if contributing:
        lines.append("[bold]Score Breakdown:[/bold]")
        for f in contributing:
            base = severity_points.get(f.severity, 0)
            points = base * f.confidence
            lines.append(
                f"  [dim]•[/dim] {f.title} → "
                f"{base} pts × {f.confidence:.0%} confidence = "
                f"[bold]{points:.0f}[/bold] pts"
            )
        lines.append(f"  [bold]Total: {pri_score}/100[/bold]")
    else:
        lines.append(f"[bold]Score: {pri_score}/100[/bold] — no risk-contributing findings")

    if informational:
        lines.append("")
        lines.append("[dim]Informational (not scored):[/dim]")
        for f in informational:
            lines.append(f"  [dim]• {f.title}[/dim]")

    console.print(Panel(
        "\n".join(lines),
        title="Score Explanation",
        border_style="dim",
        padding=(0, 2),
    ))


def _build_summary(
    target: str,
    artifact_type: str,
    findings: list[Finding],
    pri_score: int,
    modules_ran: list[str],
    modules_skipped: list[str] | None = None,
    scan_duration: float = 0.0,
    vt_result: dict | None = None,
) -> ScanSummary:
    """Build a ScanSummary from current scan state."""
    # Determine verdict from PRI score
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
    )


@app.command()
def explain(file: str = typer.Argument(help="File to explain")):
    """Explain what a file does in plain English. AI-powered behavioral analysis."""
    console.print(f"\n[bold blue]sus check explain[/bold blue]")
    console.print(f"Target: [yellow]{file}[/yellow]")
    console.print("[dim]Coming in Increment 17.[/dim]")


@app.command()
def trust(
    package: str = typer.Argument(help="Package name to assess"),
    ecosystem: str = typer.Option("pypi", "--ecosystem", "-e", help="Ecosystem: pypi, npm"),
):
    """Quick supply chain trust assessment for a package."""
    console.print(f"\n[bold blue]sus check trust[/bold blue]")
    console.print(f"Package: [yellow]{package}[/yellow] ({ecosystem})")
    console.print("[dim]Coming in Increment 9.[/dim]")


@app.command()
def install(
    ecosystem: str = typer.Argument(help="Package manager: pip, npm"),
    package: str = typer.Argument(help="Package to scan and install"),
    force: bool = typer.Option(False, "--force", help="Install even if scan finds issues"),
):
    """Scan a package, then install it if safe."""
    console.print(f"\n[bold blue]sus check install[/bold blue]")
    console.print(f"Package: [yellow]{package}[/yellow] via {ecosystem}")
    console.print("[dim]Coming in Increment 15.[/dim]")


@app.command()
def clone(
    url: str = typer.Argument(help="Repository URL to scan and clone"),
    dest: str = typer.Option(None, "--dest", "-d", help="Clone destination"),
    force: bool = typer.Option(False, "--force", help="Clone even if scan finds issues"),
):
    """Scan a repository, then clone it if safe."""
    console.print(f"\n[bold blue]sus check clone[/bold blue]")
    console.print(f"Repository: [yellow]{url}[/yellow]")
    console.print("[dim]Coming in Increment 15.[/dim]")


@app.command()
def connect(
    server: str = typer.Argument(help="MCP server URL or manifest path"),
    force: bool = typer.Option(False, "--force", help="Connect even if scan finds issues"),
):
    """Scan an MCP server, then provide connection config if safe."""
    console.print(f"\n[bold blue]sus check connect[/bold blue]")
    console.print(f"MCP Server: [yellow]{server}[/yellow]")
    console.print("[dim]Coming in Increment 15.[/dim]")


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
            f"  AI Key:        {_key_status('SUSCHECK_AI_KEY')}\n"
            f"\n[bold]External Tools:[/bold]\n"
            f"  gitleaks:  {'✅ found' if shutil.which('gitleaks') else '❌ not found'}\n"
            f"  semgrep:   {'✅ found' if shutil.which('semgrep') else '❌ not found'}\n"
            f"  bandit:    {'✅ found' if shutil.which('bandit') else '❌ not found'}\n"
            f"  docker:    {'✅ found' if shutil.which('docker') else '❌ not found'}\n"
            f"  kics:      {'✅ found' if shutil.which('kics') else '❌ not found'}\n"
            f"\n[dim]Load API keys from .env file or environment variables.\n"
            f"See .env.example for all supported keys.[/dim]",
            title="sus check — System Info",
            border_style="blue",
        )
    )
