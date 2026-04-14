"""Scan phase orchestration helpers extracted from CLI."""

from __future__ import annotations

import os
import subprocess
import tempfile
import time
from dataclasses import dataclass, field

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from suscheck.core.finding import Finding, ScanSummary, Severity, FindingType
from suscheck.core.risk_aggregator import RiskAggregator
from suscheck.modules.code.scanner import CodeScanner
from suscheck.modules.config.scanner import ConfigScanner
from suscheck.modules.mcp.scanner import MCPScanner
from suscheck.modules.repo.scanner import RepoScanner
from suscheck.modules.reporting.terminal import (
    render_findings,
    render_scan_footer,
    render_verdict,
    render_vt_result,
)
from suscheck.services.summary_service import build_scan_summary


@dataclass
class Tier0PhaseResult:
    findings: list[Finding] = field(default_factory=list)
    vt_dict: dict | None = None
    modules_ran: list[str] = field(default_factory=list)
    short_circuit_summary: ScanSummary | None = None


def execute_tier0_phase(
    *,
    target: str,
    detection,
    upload_vt: bool,
    scan_start: float,
    console: Console,
) -> Tier0PhaseResult:
    """Execute Tier 0 hash and reputation flow for local files."""
    console.print("\n[bold]Tier 0: Hash & Reputation[/bold]")

    vt_key = os.environ.get("SUSCHECK_VT_KEY", "")
    if vt_key:
        console.print("  [green]✓[/green] VirusTotal API key configured")
    else:
        console.print("  [yellow]○[/yellow] VirusTotal: no API key — [dim]set SUSCHECK_VT_KEY or add to .env[/dim]")

    file_path = detection.file_path
    if not (file_path and os.path.isfile(str(file_path))):
        console.print("[dim]Tier 0 skipped: target is not a local file[/dim]")
        return Tier0PhaseResult(findings=[], vt_dict=None, modules_ran=[])

    from suscheck.modules.external.engine import Tier0Engine

    tier0 = Tier0Engine()
    if upload_vt:
        console.print("  [yellow]⚠️  --upload-vt: file will be uploaded to VT (becomes PUBLIC)[/yellow]")

    tier0_result = tier0.check_file(str(file_path), upload_vt=upload_vt)

    if tier0_result.hash_result:
        hash_table = Table(border_style="dim", show_header=False, padding=(0, 1))
        hash_table.add_column("Hash", style="dim bold", width=8)
        hash_table.add_column("Value", style="dim")
        hash_table.add_row("SHA-256", tier0_result.hash_result.sha256)
        hash_table.add_row("MD5", tier0_result.hash_result.md5)
        hash_table.add_row("SHA-1", tier0_result.hash_result.sha1)
        hash_table.add_row("Size", f"{tier0_result.hash_result.file_size:,} bytes")
        console.print(hash_table)

    render_vt_result(tier0_result.vt_dict)
    if tier0_result.findings:
        render_findings(tier0_result.findings)

    if tier0_result.short_circuit:
        console.print(
            Panel(
                "[bold red]⚡ SHORT-CIRCUIT: Known malicious file detected.\n"
                "Scan terminated at Tier 0. No further analysis needed.[/bold red]",
                border_style="red",
                title="⚡ Short-Circuit",
            )
        )

        aggregator = RiskAggregator(detection.artifact_type.value)
        pri_result = aggregator.calculate(tier0_result.findings, tier0_result.vt_dict)

        final_score = max(prior_score := pri_result.score, 100)
        if prior_score < 100:
            pri_result.breakdown.insert(
                -1,
                "  [red]⚡ Tier 0 Short-Circuit[/red] (Known Malicious Hash) -> bumped score to [bold]100/100[/bold]",
            )
            pri_result.breakdown[-1] = "  [bold]Total Score: 100/100[/bold]"

        summary = build_scan_summary(
            target=target,
            artifact_type=detection.artifact_type.value,
            findings=tier0_result.findings,
            pri_score=final_score,
            modules_ran=["tier0"],
            scan_duration=time.time() - scan_start,
            vt_result=tier0_result.vt_dict,
            pri_breakdown=pri_result.breakdown,
        )

        console.print(
            Panel(
                "\n".join(pri_result.breakdown),
                title="Score Explanation",
                border_style="dim",
                padding=(0, 2),
            )
        )
        render_verdict(summary)
        render_scan_footer(summary)
        return Tier0PhaseResult(
            findings=tier0_result.findings,
            vt_dict=tier0_result.vt_dict,
            modules_ran=["tier0"],
            short_circuit_summary=summary,
        )

    console.print(f"[dim]Tier 0 completed in {tier0_result.scan_duration:.2f}s[/dim]")
    for error in tier0_result.errors or []:
        console.print(f"[yellow]⚠️ {error}[/yellow]")

    return Tier0PhaseResult(
        findings=tier0_result.findings,
        vt_dict=tier0_result.vt_dict,
        modules_ran=["tier0"],
        short_circuit_summary=None,
    )


def execute_local_file_tier1_phase(
    *,
    file_path: str,
    detection,
    modules_ran: list[str],
    console: Console,
) -> tuple[list[Finding], list[str]]:
    """Execute local-file Tier 1 static fan-out orchestration."""
    console.print("\n[bold]Tier 1: Static Analysis[/bold]")

    modules_updated = list(modules_ran)
    try:
        config_scanner = ConfigScanner()
        repo_scanner = RepoScanner()
        mcp_scanner = MCPScanner()

        tier1_findings: list[Finding] = []
        tier1_errors: list[str] = []
        module_results: list[tuple[str, object]] = []

        if mcp_scanner.can_handle(detection.artifact_type.value, file_path):
            module_results.append(("mcp", mcp_scanner.scan(file_path)))

        if config_scanner.can_handle(detection.artifact_type.value, file_path):
            module_results.append(("config", config_scanner.scan(file_path)))

        run_code = (
            detection.artifact_type.value in {"code", "unknown"}
            or detection.type_mismatch
            or detection.is_polyglot
            or not module_results
        )
        if run_code:
            code_scanner = CodeScanner()
            module_results.append(("code", code_scanner.scan_file(file_path, language=detection.language.value)))

        try:
            repo_secret_findings = repo_scanner.scan_file_secrets(file_path)
            if repo_secret_findings:
                tier1_findings.extend(repo_secret_findings)
                if "repo" not in modules_updated:
                    modules_updated.append("repo")
        except Exception as e:
            tier1_errors.append(f"repo secrets pass failed: {e}")

        for module_name, result_obj in module_results:
            if module_name not in modules_updated:
                modules_updated.append(module_name)

            findings = getattr(result_obj, "findings", None) or []
            if findings:
                tier1_findings.extend(findings)

            skipped_reason = getattr(result_obj, "skipped_reason", None)
            if skipped_reason == "binary_file":
                console.print("  [dim]Skipped Scanner: Binary file[/dim]")
            elif skipped_reason == "file_too_large":
                console.print("  [dim]Skipped Scanner: File too large (>5MB)[/dim]")

            error_field = getattr(result_obj, "error", None)
            if error_field:
                tier1_errors.append(str(error_field))

            errors_field = getattr(result_obj, "errors", None)
            if errors_field:
                tier1_errors.extend([str(err) for err in errors_field if err])

        if tier1_findings:
            from suscheck.modules.external.virustotal import VirusTotalClient
            from suscheck.modules.external.abuseipdb import AbuseIPDBClient

            vt_client = VirusTotalClient()
            abuse_client = AbuseIPDBClient()

            unique_urls = set()
            unique_ips = set()

            for finding in tier1_findings:
                if finding.evidence.get("type") == "url":
                    unique_urls.add(finding.evidence.get("value"))
                elif finding.evidence.get("type") == "ipv4":
                    unique_ips.add(finding.evidence.get("value"))

            if unique_urls and vt_client.available:
                console.print(f"  [dim]Querying VirusTotal for {min(3, len(unique_urls))} URLs...[/dim]")
                for url in list(unique_urls)[:3]:
                    vt_res = vt_client.lookup_url(url)
                    if vt_res and (vt_res.detection_count or 0) > 0:
                        tier1_findings.append(
                            Finding(
                                module="virustotal",
                                finding_id=f"VT-URL-{abs(hash(url)) % 10000}",
                                title=f"Malicious URL detected: {url[:30]}...",
                                description=f"URL flagged by {vt_res.detection_count}/{vt_res.total_engines} VirusTotal engines.",
                                severity=Severity.CRITICAL if vt_res.detection_count > 3 else Severity.HIGH,
                                finding_type=FindingType.C2_INDICATOR,
                                confidence=0.9,
                                mitre_ids=["T1071"],
                                evidence={"url": url, "detections": vt_res.detection_count},
                            )
                        )

            if unique_ips and abuse_client.is_configured:
                console.print(f"  [dim]Querying AbuseIPDB for {min(3, len(unique_ips))} IP addresses...[/dim]")
                for ip in list(unique_ips)[:3]:
                    abuse_res = abuse_client.lookup_ip(ip)
                    if abuse_res and abuse_res.abuse_confidence_score > 0:
                        abuse_finding = abuse_client.create_finding(abuse_res)
                        if abuse_finding:
                            tier1_findings.append(abuse_finding)

        if tier1_findings:
            render_findings(tier1_findings)
        for err in tier1_errors:
            console.print(f"  [dim]Scanner error/skipped: {err}[/dim]")
        return tier1_findings, modules_updated
    except Exception as e:
        console.print(f"  [red]Tier 1 static scan failed: {e}[/red]")
        return [], modules_updated


def execute_semgrep_phase(*, file_path: str, console: Console) -> list[Finding]:
    """Execute Tier 2 Semgrep phase for a single local file."""
    console.print("\n[bold]Tier 2: Advanced SAST (Semgrep)[/bold]")
    semgrep_findings: list[Finding] = []
    try:
        from suscheck.modules.semgrep_runner import SemgrepRunner

        semgrep_runner = SemgrepRunner()
        if semgrep_runner.is_installed:
            console.print("  [dim]Running Semgrep rules...[/dim]")
            semgrep_result = semgrep_runner.scan_file(file_path)

            if semgrep_result.findings:
                semgrep_findings.extend(semgrep_result.findings)
                render_findings(semgrep_result.findings)
            elif not semgrep_result.errors:
                console.print("  [dim]No Semgrep vulnerabilities found.[/dim]")

            for err in semgrep_result.errors or []:
                console.print(f"  [yellow]⚠️ Semgrep Warning: {err}[/yellow]")
        else:
            console.print("  [yellow]⚠️ Semgrep not installed. Skipping Layer 2 SAST.[/yellow]")
    except Exception as e:
        console.print(f"  [red]Semgrep orchestration failed: {e}[/red]")

    return semgrep_findings


def execute_remote_repository_tier1_phase(
    *,
    target: str,
    pipeline,
    modules_ran: list[str],
    console: Console,
) -> tuple[list[Finding], list[str]]:
    """Execute repository URL clone + directory scan phase."""
    modules_updated = list(modules_ran)
    console.print("\n[bold]Tier 1: Repository Static Analysis[/bold]")
    console.print("  [dim]Remote repository detected. Cloning to a temporary workspace for scanning...[/dim]")
    try:
        with tempfile.TemporaryDirectory(prefix="suscheck-repo-") as tmpdir:
            clone_cmd = ["git", "clone", "--depth", "1", target, tmpdir]
            clone_proc = subprocess.run(clone_cmd, capture_output=True, text=True, timeout=180)
            if clone_proc.returncode != 0:
                stderr = (clone_proc.stderr or "").strip()
                raise RuntimeError(stderr or "git clone failed")

            repo_findings = pipeline.scan_directory(tmpdir)

            inferred_modules = pipeline.get_modules_ran(repo_findings)
            for module_name in inferred_modules:
                if module_name not in modules_updated:
                    modules_updated.append(module_name)

            if repo_findings:
                render_findings(repo_findings)
            else:
                console.print("  [dim]No static findings from remote repository scan.[/dim]")

            return repo_findings, modules_updated
    except Exception as e:
        console.print(f"  [yellow]Tier 1 repository scan skipped: {e}[/yellow]")
        return (
            [
                Finding(
                    module="pipeline",
                    finding_id="PIPELINE-REPO-SCAN-SKIPPED",
                    title="Repository static scan could not be completed",
                    description=(
                        "Remote repository analysis failed before static scanners ran. "
                        "Treat this result as partial and require manual review before trusting the target."
                    ),
                    severity=Severity.MEDIUM,
                    finding_type=FindingType.REVIEW_NEEDED,
                    confidence=0.95,
                    file_path=target,
                    evidence={"error": str(e)[:500]},
                    needs_human_review=True,
                    review_reason="Tier 1 repository scan failed",
                )
            ],
            modules_updated,
        )


def build_static_tier1_skip_findings(*, target: str, artifact_type: str) -> list[Finding]:
    """Return explicit static-scan skip findings for unsupported Tier 1 target forms."""
    if artifact_type != "package":
        return []
    return [
        Finding(
            module="pipeline",
            finding_id="PIPELINE-PACKAGE-STATIC-SKIPPED",
            title="Package static Tier 1 scanners were not executed",
            description=(
                "Package trust checks ran, but static Tier 1 scanners did not run for this target type. "
                "Treat this as a partial scan and review manually before approval."
            ),
            severity=Severity.LOW,
            finding_type=FindingType.REVIEW_NEEDED,
            confidence=0.95,
            file_path=target,
            evidence={"artifact_type": artifact_type},
            needs_human_review=True,
            review_reason="Package target missing static Tier 1 execution",
        )
    ]
