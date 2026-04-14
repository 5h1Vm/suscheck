from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from rich.console import Console

from suscheck.core.finding import Finding, FindingType, Severity
from suscheck.services.scan_service import (
    build_static_tier1_skip_findings,
    execute_local_file_tier1_phase,
    execute_remote_repository_tier1_phase,
    execute_semgrep_phase,
    execute_tier0_phase,
)


def test_execute_tier0_phase_skips_non_file_target() -> None:
    detection = SimpleNamespace(file_path=Path("/definitely/missing/file.py"))
    console = Console(record=True)

    result = execute_tier0_phase(
        target="requests",
        detection=detection,
        upload_vt=False,
        scan_start=0.0,
        console=console,
    )

    assert result.findings == []
    assert result.vt_dict is None
    assert result.modules_ran == []
    assert result.short_circuit_summary is None


def test_execute_local_file_tier1_phase_merges_findings(monkeypatch, tmp_path: Path) -> None:
    sample = tmp_path / "sample.py"
    sample.write_text("print('hello')\n", encoding="utf-8")

    class _Res:
        def __init__(self, findings):
            self.findings = findings
            self.skipped_reason = None
            self.error = None
            self.errors = []

    def _finding(module: str, fid: str) -> Finding:
        return Finding(
            module=module,
            finding_id=fid,
            title=f"{module} finding",
            description="test",
            severity=Severity.LOW,
            finding_type=FindingType.SUSPICIOUS_BEHAVIOR,
            confidence=0.9,
            evidence={},
        )

    monkeypatch.setattr("suscheck.services.scan_service.MCPScanner.can_handle", lambda self, *_: True)
    monkeypatch.setattr("suscheck.services.scan_service.MCPScanner.scan", lambda self, _path: _Res([_finding("mcp", "MCP-1")]))

    monkeypatch.setattr("suscheck.services.scan_service.ConfigScanner.can_handle", lambda self, *_: True)
    monkeypatch.setattr("suscheck.services.scan_service.ConfigScanner.scan", lambda self, _path: _Res([_finding("config", "CFG-1")]))

    monkeypatch.setattr(
        "suscheck.services.scan_service.CodeScanner.scan_file",
        lambda self, _path, language=None: _Res([_finding("code", "CODE-1")]),
    )

    monkeypatch.setattr(
        "suscheck.services.scan_service.RepoScanner.scan_file_secrets",
        lambda self, _path: [_finding("repo", "REPO-1")],
    )

    monkeypatch.setattr("suscheck.services.scan_service.render_findings", lambda _findings: None)

    class _VT:
        available = False

    class _Abuse:
        is_configured = False

    monkeypatch.setattr("suscheck.modules.external.virustotal.VirusTotalClient", _VT)
    monkeypatch.setattr("suscheck.modules.external.abuseipdb.AbuseIPDBClient", _Abuse)

    detection = SimpleNamespace(
        artifact_type=SimpleNamespace(value="code"),
        language=SimpleNamespace(value="python"),
        type_mismatch=False,
        is_polyglot=False,
    )

    findings, modules_ran = execute_local_file_tier1_phase(
        file_path=str(sample),
        detection=detection,
        modules_ran=["tier0"],
        console=Console(record=True),
    )

    assert len(findings) >= 3
    assert "mcp" in modules_ran
    assert "config" in modules_ran
    assert "code" in modules_ran
    assert "repo" in modules_ran


def test_execute_remote_repository_tier1_phase_clone_failure(monkeypatch) -> None:
    class _Proc:
        returncode = 1
        stderr = "git failed"

    monkeypatch.setattr(
        "suscheck.services.scan_service.subprocess.run",
        lambda *args, **kwargs: _Proc(),
    )

    findings, modules_ran = execute_remote_repository_tier1_phase(
        target="https://github.com/example/repo",
        pipeline=SimpleNamespace(
            scan_directory=lambda _path: [],
            get_modules_ran=lambda _findings: [],
        ),
        modules_ran=["tier0"],
        console=Console(record=True),
    )

    assert modules_ran == ["tier0"]
    assert len(findings) == 1
    assert findings[0].finding_id == "PIPELINE-REPO-SCAN-SKIPPED"


def test_build_static_tier1_skip_findings_for_package() -> None:
    findings = build_static_tier1_skip_findings(target="requests", artifact_type="package")
    assert len(findings) == 1
    assert findings[0].finding_id == "PIPELINE-PACKAGE-STATIC-SKIPPED"


def test_execute_semgrep_phase_when_not_installed(monkeypatch, tmp_path: Path) -> None:
    class _Runner:
        is_installed = False

    monkeypatch.setattr("suscheck.modules.semgrep_runner.SemgrepRunner", _Runner)
    findings = execute_semgrep_phase(
        file_path=str(tmp_path / "sample.py"),
        console=Console(record=True),
    )
    assert findings == []
