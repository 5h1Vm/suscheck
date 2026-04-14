"""suscheck CLI — the main entry point."""

from pathlib import Path

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel

from suscheck import __version__
from suscheck.commands.analysis_commands import register_analysis_commands
from suscheck.commands.aux_commands import register_aux_commands
from suscheck.commands.scan_commands import register_scan_command
from suscheck.core.auto_detector import AutoDetector
from suscheck.core.finding import ReportFormat
from suscheck.services.policy_service import evaluate_wrapper_policy
from suscheck.services.wrapper_service import (
    build_clone_failure_message,
    build_connect_result_panel,
    build_install_failure_message,
    execute_clone_wrapper,
    execute_install_wrapper,
    normalize_install_ecosystem,
)

# ── Load .env file ────────────────────────────────────────────
# Searches for .env in the current directory and project root.
# Environment variables already set take precedence over .env.
_project_root = Path(__file__).resolve().parent.parent.parent
load_dotenv(_project_root / ".env")  # project root .env
load_dotenv()  # current directory .env (override)

app = typer.Typer(
    name="suscheck",
    help=(
    "[bold]SusCheck — Zero-Trust Security Scanner[/bold]\n"
    "Audit code, packages, and repositories BEFORE execution.\n\n"

    "[bold cyan]USAGE[/bold cyan]\n"
    "  suscheck <command> [options]\n\n"

    "[bold cyan]WORKFLOW[/bold cyan]\n"
    "  scan        Analyze any target (file, repo, package, URL)\n"
    "  trust       Quick supply-chain risk check\n\n"

    "[bold cyan]SAFE EXECUTION[/bold cyan]\n"
    "  install     Scan → then install safely\n"
    "  clone       Scan → then clone safely\n"
    "  connect     Scan → then connect safely\n\n"

    "[bold cyan]INSIGHTS[/bold cyan]\n"
    "  explain     Explain file behavior (AI)\n"
    "  diagnostics Check tools, APIs, environment\n\n"

    "[bold cyan]SETUP[/bold cyan]\n"
    "  init        Initialize config\n"
    "  version     Show system info\n\n"

    "[bold cyan]QUICK START[/bold cyan]\n"
    "  suscheck scan requests\n"
    "  suscheck scan ./project/\n"
    "  suscheck scan https://github.com/user/repo\n\n"

    "Use 'suscheck <command> --help' for more details.\n"
),
    no_args_is_help=True,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help", "-help"], "max_content_width": 110},
)
console = Console()
detector = AutoDetector()
scan = register_scan_command(app, console=console, version=__version__)

@app.command(
    short_help="Analyze a package and install it only if it passes security checks.",
    rich_help_panel="Safe Execution",
)
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
                    "Coverage notes:\n- " + "\n- ".join(summary.coverage_notes)
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


@app.command(
    short_help="Analyze a repository and clone it only if it passes security checks.",
    rich_help_panel="Safe Execution",
)
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
                    "Coverage notes:\n- " + "\n- ".join(summary.coverage_notes)
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


@app.command(
    short_help="Analyze an MCP endpoint and connect only if it passes security checks.",
    rich_help_panel="Safe Execution",
)
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
                    "Coverage notes:\n- " + "\n- ".join(summary.coverage_notes)
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
