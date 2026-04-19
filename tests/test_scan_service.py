from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

from rich.console import Console

from suscheck.core.finding import Finding, FindingType, Severity
from suscheck.services.scan_service import (
    build_static_tier1_skip_findings,
    execute_dependency_check_phase,
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

    findings, modules_ran, modules_failed = execute_local_file_tier1_phase(
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
    assert modules_failed == []


def test_execute_remote_repository_tier1_phase_clone_failure(monkeypatch) -> None:
    monkeypatch.setattr(
        "suscheck.services.scan_service.get_tool_registry",
        lambda: SimpleNamespace(register_tool=lambda _tool: SimpleNamespace(available=True, suggestion="")),
    )

    class _Proc:
        returncode = 1
        stderr = "git failed"

    monkeypatch.setattr(
        "suscheck.services.scan_service.subprocess.run",
        lambda *args, **kwargs: _Proc(),
    )

    findings, modules_ran, modules_failed = execute_remote_repository_tier1_phase(
        target="https://github.com/example/repo",
        pipeline=SimpleNamespace(
            scan_directory_with_status=lambda _path: SimpleNamespace(findings=[], modules_ran=[], modules_failed=[]),
            get_modules_ran=lambda _findings: [],
        ),
        modules_ran=["tier0"],
        console=Console(record=True),
    )

    assert modules_ran == ["tier0"]
    assert modules_failed == ["repo"]
    assert len(findings) == 1
    assert findings[0].finding_id == "PIPELINE-REPO-SCAN-SKIPPED"
    assert findings[0].evidence["error_code"] == "PIPELINE_REPO_CLONE_FAILED"


def test_execute_remote_repository_tier1_phase_clone_timeout(monkeypatch) -> None:
    monkeypatch.setattr(
        "suscheck.services.scan_service.get_tool_registry",
        lambda: SimpleNamespace(register_tool=lambda _tool: SimpleNamespace(available=True, suggestion="")),
    )

    def _raise_timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd="git clone", timeout=180)

    monkeypatch.setattr(
        "suscheck.services.scan_service.subprocess.run",
        _raise_timeout,
    )

    findings, modules_ran, modules_failed = execute_remote_repository_tier1_phase(
        target="https://github.com/example/repo",
        pipeline=SimpleNamespace(
            scan_directory_with_status=lambda _path: SimpleNamespace(findings=[], modules_ran=[], modules_failed=[]),
            get_modules_ran=lambda _findings: [],
        ),
        modules_ran=["tier0"],
        console=Console(record=True),
    )

    assert modules_ran == ["tier0"]
    assert modules_failed == ["repo"]
    assert len(findings) == 1
    assert findings[0].finding_id == "PIPELINE-REPO-SCAN-SKIPPED"
    assert findings[0].evidence["error_code"] == "TIER1_REPO_CLONE_TIMEOUT"


def test_execute_local_file_tier1_phase_repo_secret_failure_includes_code(monkeypatch, tmp_path: Path) -> None:
    sample = tmp_path / "sample.py"
    sample.write_text("print('hello')\n", encoding="utf-8")

    class _Res:
        def __init__(self):
            self.findings = []
            self.skipped_reason = None
            self.error = None
            self.errors = []

    monkeypatch.setattr("suscheck.services.scan_service.MCPScanner.can_handle", lambda self, *_: False)
    monkeypatch.setattr("suscheck.services.scan_service.ConfigScanner.can_handle", lambda self, *_: False)
    monkeypatch.setattr("suscheck.services.scan_service.CodeScanner.scan_file", lambda self, *_args, **_kwargs: _Res())

    def _repo_fail(*_args, **_kwargs):
        raise RuntimeError("repo scanner unavailable")

    monkeypatch.setattr("suscheck.services.scan_service.RepoScanner.scan_file_secrets", _repo_fail)
    monkeypatch.setattr("suscheck.services.scan_service.render_findings", lambda _findings: None)

    detection = SimpleNamespace(
        artifact_type=SimpleNamespace(value="code"),
        language=SimpleNamespace(value="python"),
        type_mismatch=False,
        is_polyglot=False,
    )

    console = Console(record=True)
    findings, modules_ran, modules_failed = execute_local_file_tier1_phase(
        file_path=str(sample),
        detection=detection,
        modules_ran=["tier0"],
        console=console,
    )

    output = console.export_text()
    assert findings == []
    assert "code" in modules_ran
    assert "repo" in modules_failed
    assert "[TIER1_REPO_SECRETS_FAILED]" in output


def test_build_static_tier1_skip_findings_for_package() -> None:
    findings = build_static_tier1_skip_findings(target="requests", artifact_type="package")
    assert len(findings) == 1
    assert findings[0].finding_id == "PIPELINE-PACKAGE-STATIC-SKIPPED"


def test_build_static_tier1_skip_findings_non_package_is_empty() -> None:
    findings = build_static_tier1_skip_findings(target="https://example.com/repo", artifact_type="repository")
    assert findings == []


def test_execute_semgrep_phase_when_not_installed(monkeypatch, tmp_path: Path) -> None:
    class _Runner:
        is_installed = False

    monkeypatch.setattr("suscheck.modules.semgrep_runner.SemgrepRunner", _Runner)
    findings, failed = execute_semgrep_phase(
        file_path=str(tmp_path / "sample.py"),
        console=Console(record=True),
    )
    assert findings == []
    assert failed is False


def test_execute_dependency_check_phase_when_tool_missing(monkeypatch) -> None:
    class _Runner:
        is_installed = False
        missing_tool_message = "dependency-check missing"

    monkeypatch.setattr("suscheck.services.scan_service.DependencyCheckRunner", _Runner)
    findings, failed = execute_dependency_check_phase(
        target_dir=".",
        console=Console(record=True),
    )

    assert any(f.finding_id == "DEPCHK-DB-STATE" for f in findings)
    assert failed is True


def test_execute_dependency_check_phase_with_runner_errors(monkeypatch) -> None:
    class _Result:
        findings = []
        errors = ["report parse warning"]

    class _Runner:
        is_installed = True
        missing_tool_message = ""

        def scan_directory(self, _target_dir: str):
            return _Result()

    monkeypatch.setattr("suscheck.services.scan_service.DependencyCheckRunner", _Runner)
    findings, failed = execute_dependency_check_phase(
        target_dir=".",
        console=Console(record=True),
    )

    assert any(f.finding_id == "DEPCHK-DB-STATE" for f in findings)
    assert any((f.evidence or {}).get("dependency_db_state") == "unknown" for f in findings)
    assert failed is True


def test_execute_remote_repository_tier1_phase_when_git_missing(monkeypatch) -> None:
    monkeypatch.setattr(
        "suscheck.services.scan_service.get_tool_registry",
        lambda: SimpleNamespace(register_tool=lambda _tool: SimpleNamespace(available=False, suggestion="install git")),
    )

    findings, modules_ran, modules_failed = execute_remote_repository_tier1_phase(
        target="https://github.com/example/repo",
        pipeline=SimpleNamespace(
            scan_directory_with_status=lambda _path: SimpleNamespace(findings=[], modules_ran=[], modules_failed=[]),
            get_modules_ran=lambda _findings: [],
        ),
        modules_ran=["tier0"],
        console=Console(record=True),
    )

    assert modules_ran == ["tier0"]
    assert modules_failed == ["repo"]
    assert len(findings) == 1
    assert findings[0].finding_id == "PIPELINE-REPO-SCAN-SKIPPED"
    assert findings[0].evidence["error_code"] == "TOOL_NOT_FOUND"
