"""Analysis-oriented command registrations extracted from main CLI."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

from suscheck.modules.reporting.terminal import render_scan_header
from suscheck.services.analysis_service import execute_explain_indicator_phase


def register_analysis_commands(app: typer.Typer, *, console: Console, detector, version: str) -> None:
    """Register explain command on shared Typer app."""

    @app.command()
    def explain(file: str = typer.Argument(help="File to explain")):
        """Explain what a file does in plain English. AI-powered behavioral analysis."""
        from suscheck.ai.explain_engine import run_behavioral_analysis

        path = Path(file)
        if not path.exists():
            console.print(f"[bold red]error:[/bold red] File not found: {file}")
            raise typer.Exit(1)

        render_scan_header(file, "analyzing behavior...", version)

        detection = detector.detect(file)
        findings = execute_explain_indicator_phase(file=file, detection=detection, console=console)

        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            console.print(f"[bold red]error:[/bold red] Could not read file content: {e}")
            raise typer.Exit(1)

        explanation = run_behavioral_analysis(
            target=file,
            artifact_type=detection.artifact_type.value,
            findings=findings,
            file_content=content,
            console=console,
        )

        console.print()
        console.print(
            Panel(
                Markdown(explanation),
                title="🤖 Behavioral Analysis",
                subtitle=f"Model-generated analysis of {path.name}",
                border_style="magenta",
                padding=(1, 2),
            )
        )
        console.print()