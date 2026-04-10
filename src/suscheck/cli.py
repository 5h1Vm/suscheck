"""suscheck CLI — the main entry point."""

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from suscheck import __version__
from suscheck.core.auto_detector import AutoDetector

app = typer.Typer(
    name="suscheck",
    help="sus check — Pre-execution security scanning platform. Scan before you trust.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
console = Console()
detector = AutoDetector()


@app.command()
def scan(
    target: str = typer.Argument(help="File, directory, URL, or package name to scan"),
    output: str = typer.Option("terminal", "--output", "-o", help="Output format: terminal, json"),
    report: str = typer.Option(None, "--report", "-r", help="Generate report: html, markdown"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Skip AI triage, rules-only mode"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
):
    """Scan any artifact for security issues."""
    console.print(f"\n[bold blue]sus check[/bold blue] v{__version__}")
    console.print(f"Target: [yellow]{target}[/yellow]\n")

    result = detector.detect(target)

    table = Table(title="Detection Result", border_style="blue")
    table.add_column("Property", style="bold")
    table.add_column("Value")

    table.add_row("Artifact Type", f"[cyan]{result.artifact_type.value}[/cyan]")
    table.add_row("Language/Format", f"[green]{result.language.value}[/green]")
    table.add_row("Detection Method", result.detection_method)
    table.add_row("Confidence", f"{result.confidence:.0%}")
    table.add_row("File Path", str(result.file_path))

    if result.magic_description:
        table.add_row("Magic Description", result.magic_description)

    if result.is_polyglot:
        langs = ", ".join(l.value for l in result.secondary_languages)
        table.add_row("[yellow]⚠️ Polyglot[/yellow]", f"[yellow]Also detected as: {langs}[/yellow]")

    if result.type_mismatch:
        table.add_row("[red]🚨 Mismatch[/red]", f"[red]{result.mismatch_detail}[/red]")

    console.print(table)
    console.print("\n[dim]Scanning modules coming in Increment 2+.[/dim]")


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

    console.print(
        Panel(
            f"[bold blue]sus check[/bold blue] v{__version__}\n"
            f"Python {sys.version.split()[0]}\n"
            f"\n[bold]External Tools:[/bold]\n"
            f"  gitleaks:  {'✅ found' if shutil.which('gitleaks') else '❌ not found'}\n"
            f"  semgrep:   {'✅ found' if shutil.which('semgrep') else '❌ not found'}\n"
            f"  bandit:    {'✅ found' if shutil.which('bandit') else '❌ not found'}\n"
            f"  docker:    {'✅ found' if shutil.which('docker') else '❌ not found'}\n"
            f"  kics:      {'✅ found' if shutil.which('kics') else '❌ not found'}",
            title="sus check — System Info",
            border_style="blue",
        )
    )
