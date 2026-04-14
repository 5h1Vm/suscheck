from __future__ import annotations

import asyncio
from types import SimpleNamespace

from typer.testing import CliRunner

from suscheck.ai.triage_engine import check_provider_health
from suscheck.cli import app


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


def test_version_command_runs() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "sus check" in result.output.lower()


def test_connect_force_uses_scan_result(monkeypatch) -> None:
    called: dict[str, object] = {}

    def fake_scan(**kwargs):
        called["scan_kwargs"] = kwargs
        return _DummySummary(pri_score=20, verdict_value="HOLD")

    def fake_connect_mcp(target: str, pri_score: float, force: bool = False):
        called["connect_args"] = (target, pri_score, force)
        return {"target": target, "pri_score": pri_score, "can_proceed": True}

    monkeypatch.setattr("suscheck.cli.scan", fake_scan)
    monkeypatch.setattr("suscheck.cli.connect_mcp", fake_connect_mcp)

    result = runner.invoke(app, ["connect", "foo", "--force"])

    assert result.exit_code == 0
    assert called["scan_kwargs"]["target"] == "foo"
    assert called["connect_args"] == ("foo", 20, True)


def test_install_force_uses_scan_result(monkeypatch) -> None:
    called: dict[str, object] = {}

    def fake_scan(**kwargs):
        called["scan_kwargs"] = kwargs
        return _DummySummary(pri_score=0, verdict_value="CLEAR")

    def fake_install_package(ecosystem: str, package: str, force: bool = False):
        called["install_args"] = (ecosystem, package, force)
        return 0

    monkeypatch.setattr("suscheck.cli.scan", fake_scan)
    monkeypatch.setattr("suscheck.cli.install_package", fake_install_package)

    result = runner.invoke(app, ["install", "pip", "requests", "--force"])

    assert result.exit_code == 0
    assert called["scan_kwargs"]["target"] == "pypi:requests"
    assert called["install_args"] == ("pypi", "requests", False)


def test_clone_force_uses_scan_result(monkeypatch) -> None:
    called: dict[str, object] = {}

    def fake_scan(**kwargs):
        called["scan_kwargs"] = kwargs
        return _DummySummary(pri_score=0, verdict_value="CLEAR")

    def fake_clone_repo(url: str, dest=None):
        called["clone_args"] = (url, dest)
        return 0

    monkeypatch.setattr("suscheck.cli.scan", fake_scan)
    monkeypatch.setattr("suscheck.cli.clone_repo", fake_clone_repo)

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

    def fake_install_package(ecosystem: str, package: str, force: bool = False):
        called["install_called"] = True
        return 0

    monkeypatch.setattr("suscheck.cli.scan", fake_scan)
    monkeypatch.setattr("suscheck.cli.install_package", fake_install_package)

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

    def fake_clone_repo(url: str, dest=None):
        called["clone_called"] = True
        return 0

    monkeypatch.setattr("suscheck.cli.scan", fake_scan)
    monkeypatch.setattr("suscheck.cli.clone_repo", fake_clone_repo)

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

    def fake_connect_mcp(target: str, pri_score: float, force: bool = False):
        called["connect_called"] = True
        return {"target": target, "pri_score": pri_score, "can_proceed": True}

    monkeypatch.setattr("suscheck.cli.scan", fake_scan)
    monkeypatch.setattr("suscheck.cli.connect_mcp", fake_connect_mcp)

    result = runner.invoke(app, ["connect", "mcp://example.local"])

    assert result.exit_code == 1
    assert called["connect_called"] is False
    assert "Partial Coverage" in result.output
