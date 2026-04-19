from __future__ import annotations

import asyncio
from types import SimpleNamespace

from rich.panel import Panel
from rich.console import Console
from typer.testing import CliRunner

from suscheck.ai.triage_engine import check_provider_health
from suscheck.cli import app
from suscheck.modules.reporting.terminal import render_scan_footer


runner = CliRunner()


class _DummySummary:
    def __init__(
        self,
        pri_score: int = 0,
        verdict_value: str = "CLEAR",
        coverage_complete: bool = True,
        coverage_notes: list[str] | None = None,
    ) -> None:
        self.pri_score = pri_score
        self.verdict = SimpleNamespace(value=verdict_value)
        self.coverage_complete = coverage_complete
        self.coverage_notes = coverage_notes or []


def test_render_scan_footer_includes_next_step_guidance(monkeypatch) -> None:
    buf_console = Console(record=True)
    monkeypatch.setattr("suscheck.modules.reporting.terminal.console", buf_console)

    summary = _DummySummary(pri_score=12, verdict_value="CLEAR", coverage_complete=True)
    summary.scan_duration = 1.23
    summary.modules_ran = ["tier0"]
    summary.modules_failed = []
    summary.modules_skipped = []
    summary.verdict = SimpleNamespace(value="CLEAR")

    render_scan_footer(summary)

    output = buf_console.export_text()
    assert "Next step:" in output


def test_version_command_runs() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "suscheck" in result.output.lower()


def test_connect_force_uses_scan_result(monkeypatch) -> None:
    called: dict[str, object] = {}

    def fake_scan(**kwargs):
        called["scan_kwargs"] = kwargs
        return _DummySummary(pri_score=20, verdict_value="HOLD")

    def fake_build_connect_result_panel(*, server: str, pri_score: float, verdict_label: str, force: bool):
        called["connect_args"] = (server, pri_score, verdict_label, force)
        return Panel("ok")

    monkeypatch.setattr("suscheck.cli.scan", fake_scan)
    monkeypatch.setattr("suscheck.cli.build_connect_result_panel", fake_build_connect_result_panel)

    result = runner.invoke(app, ["connect", "foo", "--force"])

    assert result.exit_code == 0
    assert called["scan_kwargs"]["target"] == "foo"
    assert called["connect_args"] == ("foo", 20, "HOLD", True)


def test_install_force_uses_scan_result(monkeypatch) -> None:
    called: dict[str, object] = {}

    def fake_scan(**kwargs):
        called["scan_kwargs"] = kwargs
        return _DummySummary(pri_score=0, verdict_value="CLEAR")

    def fake_execute_install_wrapper(*, trust_ecosystem: str, package: str):
        called["install_args"] = (trust_ecosystem, package)
        return 0

    monkeypatch.setattr("suscheck.cli.scan", fake_scan)
    monkeypatch.setattr("suscheck.cli.execute_install_wrapper", fake_execute_install_wrapper)

    result = runner.invoke(app, ["install", "pip", "requests", "--force"])

    assert result.exit_code == 0
    assert called["scan_kwargs"]["target"] == "pypi:requests"
    assert called["install_args"] == ("pypi", "requests")


def test_clone_force_uses_scan_result(monkeypatch) -> None:
    called: dict[str, object] = {}

    def fake_scan(**kwargs):
        called["scan_kwargs"] = kwargs
        return _DummySummary(pri_score=0, verdict_value="CLEAR")

    def fake_execute_clone_wrapper(*, url: str, dest=None):
        called["clone_args"] = (url, dest)
        return 0

    monkeypatch.setattr("suscheck.cli.scan", fake_scan)
    monkeypatch.setattr("suscheck.cli.execute_clone_wrapper", fake_execute_clone_wrapper)

    result = runner.invoke(app, ["clone", "https://github.com/example/example", "--force"])

    assert result.exit_code == 0
    assert called["scan_kwargs"]["target"] == "https://github.com/example/example"
    assert called["clone_args"] == ("https://github.com/example/example", None)


def test_check_provider_health_uses_inherited_contract(monkeypatch) -> None:
    class FakeProvider:
        name = "fake"

        def is_configured(self) -> bool:
            return True

        async def verify_connectivity(self) -> bool:
            return True

    monkeypatch.setattr("suscheck.ai.triage_engine.get_available_providers", lambda: ["fake"])
    monkeypatch.setattr("suscheck.ai.triage_engine.create_ai_provider", lambda *_: FakeProvider())

    results = asyncio.run(check_provider_health())

    assert results == {"fake": True}


def test_install_blocks_on_partial_coverage_without_force(monkeypatch) -> None:
    called: dict[str, object] = {"install_called": False}

    def fake_scan(**kwargs):
        called["scan_kwargs"] = kwargs
        return _DummySummary(
            pri_score=0,
            verdict_value="CLEAR",
            coverage_complete=False,
            coverage_notes=["PIPELINE-PACKAGE-STATIC-SKIPPED: Package static Tier 1 scanners were not executed"],
        )

    def fake_execute_install_wrapper(*, trust_ecosystem: str, package: str):
        called["install_called"] = True
        return 0

    monkeypatch.setattr("suscheck.cli.scan", fake_scan)
    monkeypatch.setattr("suscheck.cli.execute_install_wrapper", fake_execute_install_wrapper)

    result = runner.invoke(app, ["install", "pip", "requests"])

    assert result.exit_code == 1
    assert called["install_called"] is False
    assert "Partial Coverage" in result.output


def test_clone_blocks_on_partial_coverage_without_force(monkeypatch) -> None:
    called: dict[str, object] = {"clone_called": False}

    def fake_scan(**kwargs):
        called["scan_kwargs"] = kwargs
        return _DummySummary(
            pri_score=0,
            verdict_value="CLEAR",
            coverage_complete=False,
            coverage_notes=["PIPELINE-REPO-SCAN-SKIPPED: Repository static scan could not be completed"],
        )

    def fake_execute_clone_wrapper(*, url: str, dest=None):
        called["clone_called"] = True
        return 0

    monkeypatch.setattr("suscheck.cli.scan", fake_scan)
    monkeypatch.setattr("suscheck.cli.execute_clone_wrapper", fake_execute_clone_wrapper)

    result = runner.invoke(app, ["clone", "https://github.com/example/example"])

    assert result.exit_code == 1
    assert called["clone_called"] is False
    assert "Partial Coverage" in result.output


def test_connect_blocks_on_partial_coverage_without_force(monkeypatch) -> None:
    called: dict[str, object] = {"connect_called": False}

    def fake_scan(**kwargs):
        called["scan_kwargs"] = kwargs
        return _DummySummary(
            pri_score=0,
            verdict_value="CLEAR",
            coverage_complete=False,
            coverage_notes=["PIPELINE-MCP-SCAN-SKIPPED: MCP scan did not fully execute"],
        )

    def fake_build_connect_result_panel(*, server: str, pri_score: float, verdict_label: str, force: bool):
        called["connect_called"] = True
        return Panel("ok")

    monkeypatch.setattr("suscheck.cli.scan", fake_scan)
    monkeypatch.setattr("suscheck.cli.build_connect_result_panel", fake_build_connect_result_panel)

    result = runner.invoke(app, ["connect", "mcp://example.local"])

    assert result.exit_code == 1
    assert called["connect_called"] is False
    assert "Partial Coverage" in result.output
