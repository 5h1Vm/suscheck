"""Scan command registration extracted from main CLI module."""

from __future__ import annotations

import logging
import os
import sys
import time
from enum import Enum
from pathlib import Path
from types import SimpleNamespace
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from suscheck.core.auto_detector import AutoDetector, Language
from suscheck.core.config_manager import ConfigManager
from suscheck.core.finding import Finding, FindingType, ReportFormat, Severity
from suscheck.core.pipeline import ScanPipeline
from suscheck.core.routing import ScanRoute, resolve_scan_route
from suscheck.core.risk_aggregator import RiskAggregator
from suscheck.modules.mcp.dynamic import MCPDynamicScanner
from suscheck.modules.reporting.terminal import (
    render_findings,
    render_scan_footer,
    render_scan_header,
    render_verdict,
)
from suscheck.services.analysis_service import execute_ai_triage_phase, execute_package_trust_phase
from suscheck.services.policy_service import apply_partial_scan_safety_floor, evaluate_scan_policy
from suscheck.services.performance_service import evaluate_performance_guardrails
from suscheck.services.report_service import export_report
from suscheck.services.suppression_service import evaluate_suppressions, load_suppressions
from suscheck.services.trend_service import compare_and_record_trend
from suscheck.services.scan_service import (
    build_static_tier1_skip_findings,
    execute_dependency_check_phase,
    execute_grype_phase,
    execute_local_file_tier1_phase,
    execute_nuclei_phase,
    execute_openvas_phase,
    execute_remote_repository_tier1_phase,
    execute_semgrep_phase,
    execute_tier0_phase,
    execute_trivy_phase,
    execute_zap_phase,
)
from suscheck.services.summary_service import (
    build_scan_summary,
    build_explainability_trace,
    build_optional_scanner_trace,
    derive_coverage_contract,
    derive_modules_skipped,
)


class ScanProfile(str, Enum):
    DEFAULT = "default"
    DEEP = "deep"
    FAST = "fast"
    MCP_HARDENING = "mcp-hardening"


PROFILE_DEFAULTS: dict[ScanProfile, dict[str, bool]] = {
    ScanProfile.DEFAULT: {
        "ai": True,
        "vt": True,
        "dependency_check": False,
        "mcp_dynamic": False,
        "nuclei": False,
        "trivy": False,
        "grype": False,
        "zap": False,
        "openvas": False,
    },
    ScanProfile.DEEP: {
        "ai": True,
        "vt": True,
        "dependency_check": True,
        "mcp_dynamic": True,
        "nuclei": False,
        "trivy": False,
        "grype": False,
        "zap": False,
        "openvas": False,
    },
    ScanProfile.FAST: {
        "ai": False,
        "vt": False,
        "dependency_check": False,
        "mcp_dynamic": False,
        "nuclei": False,
        "trivy": False,
        "grype": False,
        "zap": False,
        "openvas": False,
    },
    ScanProfile.MCP_HARDENING: {
        "ai": True,
        "vt": True,
        "dependency_check": False,
        "mcp_dynamic": True,
        "nuclei": False,
        "trivy": False,
        "grype": False,
        "zap": False,
        "openvas": False,
    },
}


def register_scan_command(app: typer.Typer, *, console: Console, version: str):
    """Register scan command and return callable for internal wrappers."""

    @app.command(
        name="scan",
        short_help="Scan a file, package, URL, or folder and generate a risk verdict.",
        rich_help_panel="Core Workflow",
    )
    def scan(
        target: str = typer.Argument(help="File, directory, URL, or package name to scan"),
        profile: ScanProfile = typer.Option(
            ScanProfile.DEFAULT,
            "--profile",
            help="Scan preset: 'default' (balanced), 'deep' (all checks + dynamic), 'fast' (minimal), 'mcp-hardening' (MCP-focused)",
        ),
        report_format: ReportFormat = typer.Option(
            ReportFormat.TERMINAL,
            "--format",
            "-f",
            help="Report format: 'terminal' (rich output), 'json', 'markdown', 'html'",
        ),
        output: Optional[Path] = typer.Option(None, "--output", "-o", help="Save report to file (optional; default prints to terminal)"),
        ai: bool = typer.Option(False, "--ai", help="Override profile: enable AI-powered triage"),
        no_ai: bool = typer.Option(False, "--no-ai", help="Override profile: skip AI triage (rules-only mode)"),
        vt: bool = typer.Option(False, "--vt", help="Override profile: enable VirusTotal reputation checks"),
        no_vt: bool = typer.Option(False, "--no-vt", help="Override profile: skip VirusTotal lookups"),
        upload_vt: bool = typer.Option(
            False,
            "--upload-vt",
            help="With --vt: upload unknown files to VirusTotal for scanning. ⚠️  Files become PUBLIC.",
        ),
        verbose: bool = typer.Option(False, "--verbose", "-v", "-V", help="Show debug logs and tool output"),
        no_mcp_dynamic: bool = typer.Option(
            False,
            "--no-mcp-dynamic",
            help="Override profile: skip dynamic MCP observation (Docker-based testing)",
        ),
        mcp_dynamic: bool = typer.Option(
            False,
            "--mcp-dynamic",
            help="Override profile: enable MCP dynamic observation (requires Docker daemon)",
        ),
        mcp_only: bool = typer.Option(
            False,
            "--mcp-only",
            help="Run only MCP checks (skip other scanners) for local files",
        ),
        no_dependency_check: bool = typer.Option(
            False,
            "--no-dependency-check",
            help="Override profile: skip dependency vulnerability scans",
        ),
        dependency_check: bool = typer.Option(
            False,
            "--dependency-check",
            help="Override profile: enable OWASP Dependency-Check for CVEs (directories only)",
        ),
        nuclei: bool = typer.Option(
            False,
            "--nuclei",
            help="Override profile: enable Nuclei optional adapter (HTTP(S) URL targets only)",
        ),
        no_nuclei: bool = typer.Option(
            False,
            "--no-nuclei",
            help="Override profile: disable Nuclei optional adapter",
        ),
        trivy: bool = typer.Option(
            False,
            "--trivy",
            help="Override profile: enable Trivy optional adapter (local file/directory targets)",
        ),
        no_trivy: bool = typer.Option(
            False,
            "--no-trivy",
            help="Override profile: disable Trivy optional adapter",
        ),
        grype: bool = typer.Option(
            False,
            "--grype",
            help="Override profile: enable Grype optional adapter (local file/directory targets)",
        ),
        no_grype: bool = typer.Option(
            False,
            "--no-grype",
            help="Override profile: disable Grype optional adapter",
        ),
        zap: bool = typer.Option(
            False,
            "--zap",
            help="Override profile: enable ZAP optional adapter (HTTP(S) URL targets only)",
        ),
        no_zap: bool = typer.Option(
            False,
            "--no-zap",
            help="Override profile: disable ZAP optional adapter",
        ),
        openvas: bool = typer.Option(
            False,
            "--openvas",
            help="Override profile: enable OpenVAS optional adapter (URL/host targets)",
        ),
        no_openvas: bool = typer.Option(
            False,
            "--no-openvas",
            help="Override profile: disable OpenVAS optional adapter",
        ),
        report_dir: Optional[Path] = typer.Option(
            None,
            "--report-dir",
            help="Directory for multi-format reports (defaults to ./reports/)",
        ),
    ):
        """Scan any artifact for security issues."""
        if verbose:
            logging.basicConfig(level=logging.DEBUG, format="%(name)s: %(message)s")
        else:
            logging.basicConfig(level=logging.WARNING)

        scan_start = time.time()

        # Profile baseline + explicit override precedence:
        # explicit enable > explicit disable > profile default.
        defaults = PROFILE_DEFAULTS[profile]
        ai_enabled = defaults["ai"]
        if no_ai:
            ai_enabled = False
        if ai:
            ai_enabled = True

        vt_enabled = defaults["vt"]
        if no_vt:
            vt_enabled = False
        if vt:
            vt_enabled = True

        depcheck_enabled = defaults["dependency_check"]
        if no_dependency_check:
            depcheck_enabled = False
        if dependency_check:
            depcheck_enabled = True

        nuclei_enabled = defaults["nuclei"]
        if no_nuclei:
            nuclei_enabled = False
        if nuclei:
            nuclei_enabled = True

        trivy_enabled = defaults["trivy"]
        if no_trivy:
            trivy_enabled = False
        if trivy:
            trivy_enabled = True

        grype_enabled = defaults["grype"]
        if no_grype:
            grype_enabled = False
        if grype:
            grype_enabled = True

        zap_enabled = defaults["zap"]
        if no_zap:
            zap_enabled = False
        if zap:
            zap_enabled = True

        openvas_enabled = defaults["openvas"]
        if no_openvas:
            openvas_enabled = False
        if openvas:
            openvas_enabled = True

        mcp_dynamic_enabled = defaults["mcp_dynamic"]
        if no_mcp_dynamic:
            mcp_dynamic_enabled = False
        if mcp_dynamic:
            mcp_dynamic_enabled = True

        console.print(
            f"[dim]Profile={profile.value} | AI={'on' if ai_enabled else 'off'} | VT={'on' if vt_enabled else 'off'} | "
            f"DepCheck={'on' if depcheck_enabled else 'off'} | Nuclei={'on' if nuclei_enabled else 'off'} | "
            f"Trivy={'on' if trivy_enabled else 'off'} | Grype={'on' if grype_enabled else 'off'} | "
            f"ZAP={'on' if zap_enabled else 'off'} | OpenVAS={'on' if openvas_enabled else 'off'} | "
            f"MCP Dynamic={'on' if mcp_dynamic_enabled else 'off'}[/dim]"
        )

        if not vt_enabled:
            os.environ["SUSCHECK_NO_VT"] = "1"
            os.environ.pop("SUSCHECK_VT_KEY", None)
            if upload_vt:
                console.print("[yellow]--upload-vt ignored because --no-vt is set.[/yellow]")
                upload_vt = False
        else:
            os.environ.pop("SUSCHECK_NO_VT", None)

        if nuclei_enabled:
            os.environ["SUSCHECK_ENABLE_NUCLEI"] = "1"
        else:
            os.environ.pop("SUSCHECK_ENABLE_NUCLEI", None)

        if trivy_enabled:
            os.environ["SUSCHECK_ENABLE_TRIVY"] = "1"
        else:
            os.environ.pop("SUSCHECK_ENABLE_TRIVY", None)

        if grype_enabled:
            os.environ["SUSCHECK_ENABLE_GRYPE"] = "1"
        else:
            os.environ.pop("SUSCHECK_ENABLE_GRYPE", None)

        if zap_enabled:
            os.environ["SUSCHECK_ENABLE_ZAP"] = "1"
        else:
            os.environ.pop("SUSCHECK_ENABLE_ZAP", None)

        if openvas_enabled:
            os.environ["SUSCHECK_ENABLE_OPENVAS"] = "1"
        else:
            os.environ.pop("SUSCHECK_ENABLE_OPENVAS", None)

        target_path = Path(target).resolve()
        config_mgr = ConfigManager()

        if not target_path.exists() and not any(target.startswith(p) for p in ["http://", "https://"]):
            is_likely_package = "/" not in target and "\\" not in target and "." not in target
            is_likely_openvas_network_target = openvas_enabled and "/" not in target and "\\" not in target and "." in target
            if not is_likely_package and not is_likely_openvas_network_target:
                console.print(f"\n[bold red]FATAL: Artifact not found at source:[/bold red] {target}")
                console.print("[dim]Ensure the path is correct or specify a valid package name.[/dim]")
                sys.exit(1)

        detector = AutoDetector(config_mgr)
        detection = detector.detect(target)

        type_display = f"{detection.artifact_type.value.upper()}"
        if detection.language != Language.UNKNOWN:
            type_display += f" ({detection.language.value.capitalize()})"

        render_scan_header(target, type_display, version)

        pipeline = ScanPipeline(config_mgr)

        if target_path.is_dir():
            console.print(f"\n[bold blue]Recursive directory scan initiated:[/bold blue] {target}")

            with console.status(f"Scanning directory {target}...", spinner="bouncingBar"):
                dir_result = pipeline.scan_directory_with_status(target)

            all_findings = dir_result.findings
            modules_failed = list(dir_result.modules_failed)
            modules_ran = list(dir_result.modules_ran or pipeline.get_modules_ran(all_findings))

            if depcheck_enabled:
                dep_findings, dep_failed = execute_dependency_check_phase(target_dir=target, console=console)
                if dep_findings:
                    all_findings.extend(dep_findings)
                if "dependency_check" not in modules_ran:
                    modules_ran.append("dependency_check")
                if dep_failed and "dependency_check" not in modules_failed:
                    modules_failed.append("dependency_check")
                if dep_failed:
                    all_findings.append(
                        Finding(
                            module="pipeline",
                            finding_id="PIPELINE-DEPENDENCY-CHECK-SKIPPED",
                            title="Dependency-Check phase did not fully execute",
                            description=(
                                "Dependency vulnerability analysis reported an execution/tooling issue. "
                                "Treat dependency coverage as partial and verify dependency risk manually."
                            ),
                            severity=Severity.LOW,
                            finding_type=FindingType.REVIEW_NEEDED,
                            confidence=0.95,
                            file_path=target,
                            evidence={"phase": "dependency_check"},
                            needs_human_review=True,
                            review_reason="Dependency-Check phase failed",
                        )
                    )
            suppressions = load_suppressions(os.environ.get("SUSCHECK_SUPPRESSIONS_FILE"))
            suppression_trace: list[str] = []
            if suppressions:
                suppression_result = evaluate_suppressions(all_findings, suppressions)
                if suppression_result.findings:
                    all_findings.extend(suppression_result.findings)
                suppression_trace = suppression_result.trace
                if suppression_result.trace:
                    console.print(f"[dim]Suppression governance entries loaded: {suppression_result.loaded_entries}[/dim]")
            scan_duration = time.time() - scan_start

            perf_result = evaluate_performance_guardrails(
                profile=profile.value,
                summary=SimpleNamespace(scan_duration=scan_duration),
            )
            if perf_result.findings:
                all_findings.extend(perf_result.findings)
            performance_trace = perf_result.trace

            aggregator = RiskAggregator("DIRECTORY")
            pri_result = aggregator.calculate(all_findings)

            modules_skipped = derive_modules_skipped(
                artifact_type="DIRECTORY",
                modules_ran=modules_ran,
                file_path=None,
                mcp_dynamic_enabled=mcp_dynamic_enabled,
            )
            coverage_complete, coverage_notes = derive_coverage_contract(
                all_findings,
                modules_skipped,
                artifact_type="DIRECTORY",
                modules_ran=modules_ran,
                modules_failed=modules_failed,
                mcp_dynamic_enabled=mcp_dynamic_enabled,
            )
            if not dir_result.coverage_complete:
                coverage_complete = False
                coverage_notes.append(
                    f"Directory coverage: {dir_result.files_scanned}/{dir_result.files_total} files ({dir_result.coverage_pct}%)"
                )

            summary = build_scan_summary(
                target=target,
                artifact_type="DIRECTORY",
                findings=all_findings,
                pri_score=pri_result.score,
                modules_ran=list(modules_ran),
                modules_failed=sorted(set(modules_failed)),
                modules_skipped=modules_skipped,
                coverage_complete=coverage_complete,
                coverage_notes=coverage_notes,
                scan_duration=scan_duration,
                verdict=pri_result.verdict,
                pri_breakdown=pri_result.breakdown,
            )
            summary.suppression_trace = suppression_trace
            policy_decision = evaluate_scan_policy(summary)
            summary.policy_action = policy_decision.action
            summary.policy_trace = policy_decision.trace
            summary.explainability_trace = build_explainability_trace(summary)
            summary.performance_trace = performance_trace
            trend_result = compare_and_record_trend(summary)
            summary.trend_trace = trend_result.trace
            summary.optional_scanner_trace = build_optional_scanner_trace()

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
            langs = ", ".join(lang.value for lang in detection.secondary_languages)
            table.add_row(
                "[yellow]⚠️ Polyglot[/yellow]",
                f"[yellow]Also detected as: {langs}[/yellow]",
            )

        if detection.type_mismatch:
            table.add_row("[red]🚨 Mismatch[/red]", f"[red]{detection.mismatch_detail}[/red]")

        console.print(table)

        all_findings: list[Finding] = []
        modules_failed: list[str] = []

        if detection.type_mismatch:
            all_findings.append(
                Finding(
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
                    mitre_ids=["T1036.008"],
                    evidence={
                        "mismatch_detail": detection.mismatch_detail,
                        "detection_method": detection.detection_method,
                    },
                )
            )

        if detection.is_polyglot:
            secondary = ", ".join(lang.value for lang in detection.secondary_languages)
            all_findings.append(
                Finding(
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
                    mitre_ids=["T1027.009"],
                    needs_human_review=True,
                    review_reason="Polyglot file — scan as all detected types",
                )
            )

        file_path = detection.file_path
        tier0_phase = execute_tier0_phase(
            target=target,
            detection=detection,
            no_vt=not vt_enabled,
            upload_vt=upload_vt,
            scan_start=scan_start,
            console=console,
        )
        if tier0_phase.short_circuit_summary is not None:
            return tier0_phase.short_circuit_summary

        all_findings.extend(tier0_phase.findings)
        vt_dict = tier0_phase.vt_dict
        modules_ran = tier0_phase.modules_ran
        modules_failed.extend(tier0_phase.modules_failed)

        route = resolve_scan_route(target=target, target_path=target_path, detection=detection)

        if route == ScanRoute.LOCAL_FILE and file_path and os.path.isfile(str(file_path)):
            tier1_findings, modules_ran, tier1_failed = execute_local_file_tier1_phase(
                file_path=str(file_path),
                detection=detection,
                modules_ran=modules_ran,
                no_vt=not vt_enabled,
                mcp_only=mcp_only,
                console=console,
            )
            modules_failed.extend(tier1_failed)
            if tier1_findings:
                all_findings.extend(tier1_findings)

            if mcp_dynamic_enabled and file_path and os.path.isfile(str(file_path)) and "mcp" in modules_ran:
                try:
                    dyn = MCPDynamicScanner()
                    if dyn.can_handle(detection.artifact_type.value, str(file_path)):
                        console.print("\n[bold]MCP Dynamic (Docker)[/bold]")
                        dyn_res = dyn.scan(str(file_path))
                        if "mcp_dynamic" not in modules_ran:
                            modules_ran.append("mcp_dynamic")
                        all_findings.extend(dyn_res.findings)
                        if dyn_res.error:
                            if "mcp_dynamic" not in modules_failed:
                                modules_failed.append("mcp_dynamic")
                            all_findings.append(
                                Finding(
                                    module="pipeline",
                                    finding_id="PIPELINE-MCP-DYNAMIC-SKIPPED",
                                    title="MCP dynamic observation did not fully execute",
                                    description=(
                                        "MCP dynamic/runtime observation returned an error. "
                                        "Treat scan coverage as partial and validate runtime behavior manually."
                                    ),
                                    severity=Severity.LOW,
                                    finding_type=FindingType.REVIEW_NEEDED,
                                    confidence=0.95,
                                    file_path=str(file_path),
                                    evidence={"error": str(dyn_res.error)[:240]},
                                    needs_human_review=True,
                                    review_reason="MCP dynamic phase failed",
                                )
                            )
                            console.print(f"  [dim]MCP dynamic: {dyn_res.error}[/dim]")
                        for note in dyn_res.metadata.get("observations") or []:
                            if note.get("error"):
                                console.print(f"  [dim]  server {note.get('server')}: {note['error']}[/dim]")
                            elif note.get("skip"):
                                console.print(f"  [dim]  server {note.get('server')}: skipped ({note['skip']})[/dim]")
                        if dyn_res.findings:
                            render_findings(dyn_res.findings)
                        elif not dyn_res.error:
                            console.print("  [dim]MCP dynamic finished (no findings from observation).[/dim]")
                except Exception as e:
                    if "mcp_dynamic" not in modules_failed:
                        modules_failed.append("mcp_dynamic")
                    all_findings.append(
                        Finding(
                            module="pipeline",
                            finding_id="PIPELINE-MCP-DYNAMIC-SKIPPED",
                            title="MCP dynamic observation failed before completion",
                            description=(
                                "MCP dynamic/runtime observation crashed or could not be executed. "
                                "Treat scan coverage as partial and review manually."
                            ),
                            severity=Severity.LOW,
                            finding_type=FindingType.REVIEW_NEEDED,
                            confidence=0.95,
                            file_path=str(file_path),
                            evidence={"error": str(e)[:240]},
                            needs_human_review=True,
                            review_reason="MCP dynamic phase failed",
                        )
                    )
                    console.print(f"  [yellow]MCP dynamic observation failed: {e}[/yellow]")

            semgrep_findings, semgrep_failed = execute_semgrep_phase(file_path=str(file_path), console=console)
            if semgrep_failed:
                modules_failed.append("semgrep")
                all_findings.append(
                    Finding(
                        module="pipeline",
                        finding_id="PIPELINE-SEMGREP-SCAN-SKIPPED",
                        title="Semgrep phase did not fully execute",
                        description=(
                            "Semgrep static analysis reported execution/tooling issues. "
                            "Treat code security coverage as partial for this run."
                        ),
                        severity=Severity.LOW,
                        finding_type=FindingType.REVIEW_NEEDED,
                        confidence=0.95,
                        file_path=str(file_path),
                        evidence={"phase": "semgrep"},
                        needs_human_review=True,
                        review_reason="Semgrep phase failed",
                    )
                )
            if semgrep_findings:
                all_findings.extend(semgrep_findings)

        elif route == ScanRoute.REMOTE_REPOSITORY:
            repo_findings, modules_ran, repo_failed = execute_remote_repository_tier1_phase(
                target=target,
                pipeline=pipeline,
                modules_ran=modules_ran,
                console=console,
            )
            modules_failed.extend(repo_failed)
            all_findings.extend(repo_findings)
        else:
            console.print("\n[bold]Tier 1: Static Analysis[/bold]")
            console.print("  [dim]Tier 1 skipped: static scanners currently require a local file or repository target.[/dim]")
            all_findings.extend(
                build_static_tier1_skip_findings(target=target, artifact_type=detection.artifact_type.value)
            )

        nuclei_findings, nuclei_failed = execute_nuclei_phase(
            target=target,
            enabled=nuclei_enabled,
            console=console,
        )
        if nuclei_enabled and "nuclei" not in modules_ran:
            modules_ran.append("nuclei")
        if nuclei_failed and "nuclei" not in modules_failed:
            modules_failed.append("nuclei")
        if nuclei_findings:
            all_findings.extend(nuclei_findings)

        trivy_findings, trivy_failed = execute_trivy_phase(
            target=target,
            enabled=trivy_enabled,
            console=console,
        )
        if trivy_enabled and "trivy" not in modules_ran:
            modules_ran.append("trivy")
        if trivy_failed and "trivy" not in modules_failed:
            modules_failed.append("trivy")
        if trivy_findings:
            all_findings.extend(trivy_findings)

        grype_findings, grype_failed = execute_grype_phase(
            target=target,
            enabled=grype_enabled,
            console=console,
        )
        if grype_enabled and "grype" not in modules_ran:
            modules_ran.append("grype")
        if grype_failed and "grype" not in modules_failed:
            modules_failed.append("grype")
        if grype_findings:
            all_findings.extend(grype_findings)

        zap_findings, zap_failed = execute_zap_phase(
            target=target,
            enabled=zap_enabled,
            console=console,
        )
        if zap_enabled and "zap" not in modules_ran:
            modules_ran.append("zap")
        if zap_failed and "zap" not in modules_failed:
            modules_failed.append("zap")
        if zap_findings:
            all_findings.extend(zap_findings)

        openvas_findings, openvas_failed = execute_openvas_phase(
            target=target,
            enabled=openvas_enabled,
            console=console,
        )
        if openvas_enabled and "openvas" not in modules_ran:
            modules_ran.append("openvas")
        if openvas_failed and "openvas" not in modules_failed:
            modules_failed.append("openvas")
        if openvas_findings:
            all_findings.extend(openvas_findings)

        scan_duration = time.time() - scan_start

        perf_result = evaluate_performance_guardrails(
            profile=profile.value,
            summary=SimpleNamespace(scan_duration=scan_duration),
        )
        if perf_result.findings:
            all_findings.extend(perf_result.findings)
        performance_trace = perf_result.trace

        suppressions = load_suppressions(os.environ.get("SUSCHECK_SUPPRESSIONS_FILE"))
        if suppressions:
            suppression_result = evaluate_suppressions(all_findings, suppressions)
            if suppression_result.findings:
                all_findings.extend(suppression_result.findings)
            if suppression_result.trace:
                console.print(f"[dim]Suppression governance entries loaded: {suppression_result.loaded_entries}[/dim]")
            suppression_trace = suppression_result.trace
        else:
            suppression_trace = []

        supply_chain_trust_score, trust_findings, modules_ran = execute_package_trust_phase(
            target=target,
            artifact_type=detection.artifact_type.value,
            modules_ran=modules_ran,
            console=console,
        )
        if trust_findings:
            all_findings.extend(trust_findings)

        ai_pri_delta, modules_ran = execute_ai_triage_phase(
            no_ai=not ai_enabled,
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
            mcp_dynamic_enabled=mcp_dynamic_enabled,
        )
        coverage_complete, coverage_notes = derive_coverage_contract(
            all_findings,
            modules_skipped,
            artifact_type=detection.artifact_type.value,
            modules_ran=modules_ran,
            modules_failed=modules_failed,
            mcp_dynamic_enabled=mcp_dynamic_enabled,
        )

        summary = build_scan_summary(
            target=target,
            artifact_type=detection.artifact_type.value,
            findings=all_findings,
            pri_score=pri_result.score,
            modules_ran=modules_ran,
            modules_failed=sorted(set(modules_failed)),
            modules_skipped=modules_skipped,
            coverage_complete=coverage_complete,
            coverage_notes=coverage_notes,
            scan_duration=scan_duration,
            vt_result=vt_dict,
            trust_score=supply_chain_trust_score,
            verdict=pri_result.verdict,
            pri_breakdown=pri_result.breakdown,
        )
        summary.suppression_trace = suppression_trace
        policy_decision = evaluate_scan_policy(summary)
        summary.policy_action = policy_decision.action
        summary.policy_trace = policy_decision.trace
        summary.explainability_trace = build_explainability_trace(summary)
        summary.performance_trace = performance_trace
        trend_result = compare_and_record_trend(summary)
        summary.trend_trace = trend_result.trace
        summary.optional_scanner_trace = build_optional_scanner_trace()

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

    return scan
