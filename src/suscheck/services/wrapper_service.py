"""Wrapper execution and rendering helpers extracted from CLI."""

from __future__ import annotations

from typing import Optional

from rich.panel import Panel

from suscheck.modules.wrappers.clone import clone_repo
from suscheck.modules.wrappers.connect import connect_mcp
from suscheck.modules.wrappers.install import install_package


def normalize_install_ecosystem(ecosystem: str) -> str | None:
    """Normalize user ecosystem input for trust/install wrappers."""
    eco = ecosystem.lower()
    if eco in ("pip", "pypi"):
        return "pypi"
    if eco == "npm":
        return "npm"
    return None


def execute_install_wrapper(*, trust_ecosystem: str, package: str) -> int:
    """Execute package install wrapper and return process exit code."""
    return install_package(trust_ecosystem, package)


def execute_clone_wrapper(*, url: str, dest: Optional[str]) -> int:
    """Execute repository clone wrapper and return process exit code."""
    return clone_repo(url, dest)


def build_install_failure_message(return_code: int) -> str:
    """Build consistent installer failure message for CLI rendering."""
    if return_code == 127:
        return "Failed to run installer command: installer not found."
    return f"Installer exited with non-zero status code {return_code}."


def build_clone_failure_message(return_code: int) -> str:
    """Build consistent clone failure message for CLI rendering."""
    if return_code == 127:
        return "Failed to run git command: git not found."
    return f"git clone exited with non-zero status code {return_code}."


def build_connect_result_panel(*, server: str, pri_score: float, verdict_label: str, force: bool) -> Panel:
    """Build final connect status panel and execute wrapper when forced."""
    if force:
        res = connect_mcp(server, pri_score, force=True)
        return Panel(
            (
                "[bold red]WARNING:[/bold red] Allowing MCP connection despite elevated PRI score "
                f"({res['pri_score']}/100, {verdict_label}) "
                "because [yellow]--force[/yellow] was specified.\n\n"
                "[dim]suscheck does not perform the connection itself; configure your MCP client "
                "using the scan results above.[/dim]"
            ),
            border_style="red",
            padding=(1, 2),
        )

    return Panel(
        (
            "[bold green]SusCheck did not block this MCP target.[/bold green]\n\n"
            f"PRI score: [bold]{pri_score}/100[/bold] ({verdict_label}).\n"
            "You may now add this server to your MCP client configuration.\n"
            "[dim]Note: suscheck does not create or modify client configs automatically.[/dim]"
        ),
        border_style="green",
        padding=(1, 2),
    )