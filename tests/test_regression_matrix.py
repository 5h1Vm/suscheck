from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from suscheck.cli import app
from suscheck.core.finding import Finding, FindingType, Severity


runner = CliRunner()


def _finding(*, module: str, fid: str) -> Finding:
    return Finding(
        module=module,
        finding_id=fid,
        title=f"{module}:{fid}",
        description="test",
        severity=Severity.LOW,
        finding_type=FindingType.SUSPICIOUS_BEHAVIOR,
        confidence=0.9,
        evidence={},
    )


def _patch_common(monkeypatch) -> None:
    # Keep matrix tests deterministic and independent from external systems.
    monkeypatch.setattr(
        "suscheck.commands.scan_commands.execute_tier0_phase",
        lambda **_kwargs: SimpleNamespace(
            findings=[],
            vt_dict=None,
            modules_ran=["tier0"],
            modules_failed=[],
            short_circuit_summary=None,
        ),
    )
    monkeypatch.setattr(
        "suscheck.commands.scan_commands.execute_package_trust_phase",
        lambda **_kwargs: (None, [], _kwargs["modules_ran"]),
    )
    monkeypatch.setattr(
        "suscheck.commands.scan_commands.execute_ai_triage_phase",
        lambda **_kwargs: (0.0, _kwargs["modules_ran"]),
    )


@pytest.mark.parametrize(
    "scenario_name,target_kind,profile,extra_flags,expected_failed_module,expected_finding_id",
    [
        (
            "package_fast_default_partial",
            "package",
            "fast",
            ["--no-ai"],
            None,
            "PIPELINE-PACKAGE-STATIC-SKIPPED",
        ),
        (
            "repo_default_tool_missing",
            "repository",
            "default",
            ["--no-ai"],
            "repo",
            "PIPELINE-REPO-SCAN-SKIPPED",
        ),
        (
            "directory_deep_depcheck_failure",
            "directory",
            "deep",
            ["--dependency-check", "--no-ai"],
            "dependency_check",
            "PIPELINE-DEPENDENCY-CHECK-SKIPPED",
        ),
        (
            "local_fast_semgrep_failure",
            "local_file",
            "fast",
            ["--no-ai", "--no-vt"],
            "semgrep",
            "PIPELINE-SEMGREP-SCAN-SKIPPED",
        ),
        (
            "local_mcp_dynamic_failure",
            "mcp_file",
            "mcp-hardening",
            ["--mcp-only", "--mcp-dynamic", "--no-ai", "--no-vt"],
            "mcp_dynamic",
            "PIPELINE-MCP-DYNAMIC-SKIPPED",
        ),
    ],
)
def test_scan_regression_matrix(
    monkeypatch,
    tmp_path: Path,
    scenario_name: str,
    target_kind: str,
    profile: str,
    extra_flags: list[str],
    expected_failed_module: str | None,
    expected_finding_id: str,
) -> None:
    _patch_common(monkeypatch)

    # Matrix axis: target type x profile x flags x tool/failure mode.
    if target_kind == "package":
        target = "requests"

    elif target_kind == "repository":
        target = "https://github.com/example/repo"
        monkeypatch.setattr(
            "suscheck.commands.scan_commands.execute_remote_repository_tier1_phase",
            lambda **kwargs: (
                [
                    Finding(
                        module="pipeline",
                        finding_id="PIPELINE-REPO-SCAN-SKIPPED",
                        title="Repository static scan could not be completed",
                        description="partial",
                        severity=Severity.MEDIUM,
                        finding_type=FindingType.REVIEW_NEEDED,
                        confidence=0.95,
                        file_path=kwargs["target"],
                        evidence={"error_code": "TOOL_NOT_FOUND"},
                        needs_human_review=True,
                        review_reason="repo tool missing",
                    )
                ],
                kwargs["modules_ran"],
                ["repo"],
            ),
        )

    elif target_kind == "directory":
        target = str(tmp_path)

        class _DirResult:
            findings = []
            modules_ran = ["repo"]
            modules_failed = []
            coverage_complete = True
            files_scanned = 1
            files_total = 1
            coverage_pct = 100

        monkeypatch.setattr(
            "suscheck.commands.scan_commands.ScanPipeline.scan_directory_with_status",
            lambda self, _path: _DirResult(),
        )
        monkeypatch.setattr(
            "suscheck.commands.scan_commands.execute_dependency_check_phase",
            lambda **_kwargs: ([], True),
        )

    elif target_kind == "local_file":
        sample = tmp_path / "sample.py"
        sample.write_text("print('ok')\n", encoding="utf-8")
        target = str(sample)

        monkeypatch.setattr(
            "suscheck.commands.scan_commands.execute_local_file_tier1_phase",
            lambda **kwargs: ([ _finding(module="code", fid="CODE-1") ], kwargs["modules_ran"] + ["code"], []),
        )
        monkeypatch.setattr(
            "suscheck.commands.scan_commands.execute_semgrep_phase",
            lambda **_kwargs: ([], True),
        )

    elif target_kind == "mcp_file":
        sample = tmp_path / "mcp.json"
        sample.write_text('{"mcpServers": {"demo": {"command": "node", "args": ["server.js"]}}}', encoding="utf-8")
        target = str(sample)

        monkeypatch.setattr(
            "suscheck.commands.scan_commands.execute_local_file_tier1_phase",
            lambda **kwargs: ([ _finding(module="mcp", fid="MCP-1") ], kwargs["modules_ran"] + ["mcp"], []),
        )
        monkeypatch.setattr("suscheck.commands.scan_commands.execute_semgrep_phase", lambda **_kwargs: ([], False))

        class _DynResult:
            def __init__(self) -> None:
                self.findings = []
                self.error = "docker unavailable"
                self.metadata = {}

        monkeypatch.setattr("suscheck.commands.scan_commands.MCPDynamicScanner.can_handle", lambda self, *_: True)
        monkeypatch.setattr("suscheck.commands.scan_commands.MCPDynamicScanner.scan", lambda self, _path: _DynResult())

    else:
        raise AssertionError(f"Unknown matrix scenario: {scenario_name}")

    report_path = tmp_path / f"{scenario_name}.json"
    result = runner.invoke(
        app,
        [
            "scan",
            target,
            "--profile",
            profile,
            *extra_flags,
            "--format",
            "json",
            "--output",
            str(report_path),
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(report_path.read_text(encoding="utf-8"))

    if expected_failed_module is not None:
        assert expected_failed_module in payload["modules_failed"]
    assert any(f["finding_id"] == expected_finding_id for f in payload["findings"])
