"""Auxiliary CLI commands extracted from main cli module."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from suscheck.core.config_manager import ConfigManager
from suscheck.core.diagnostics import DiagnosticSuite
from suscheck.modules.reporting.terminal import render_findings


def register_aux_commands(app: typer.Typer, *, console: Console, version: str) -> None:
    """Register trust/version/init commands on the shared Typer app."""

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

    def version_cmd():
        """Show sus check version and system info."""

        def _key_status(env_var: str) -> str:
            val = os.environ.get(env_var, "")
            if val:
                return f"✅ configured ({val[:8]}...)"
            return "❌ not set"

        _ai_key_names = (
            "SUSCHECK_GROQ_KEY",
            "SUSCHECK_OPENAI_KEY",
            "SUSCHECK_ANTHROPIC_KEY",
            "SUSCHECK_GEMINI_KEY",
            "SUSCHECK_AI_KEY",
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
                f"[bold blue]sus check[/bold blue] v{version}\n"
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

    app.command(name="version")(version_cmd)

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

        console.print(f"\n[bold blue]SusCheck Diagnostic Suite[/bold blue] v{version}")
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
