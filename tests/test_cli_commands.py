from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from suscheck.cli import app
from suscheck.core.auto_detector import ArtifactType, DetectionResult, Language
from suscheck.core.finding import Finding, FindingType, Severity


runner = CliRunner()


def test_scan_missing_target_exits_nonzero() -> None:
    # Use a non-existent path-like target so CLI does not treat it as package name.
    result = runner.invoke(app, ["scan", "./definitely_missing_target_12345/not_found.py"])
    assert result.exit_code != 0
    assert "Artifact not found" in result.output


def test_diagnostics_command_runs_with_stubbed_suite(monkeypatch) -> None:
    class _Result:
        def __init__(self, service: str, status: str, message: str) -> None:
            self.service = service
            self.status = status
            self.message = message

    class _Suite:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def run_all(self):
            return [
                _Result("VirusTotal", "OK", "reachable"),
                _Result("deps.dev", "SKIPPED", "no key needed"),
            ]

    monkeypatch.setattr("suscheck.commands.aux_commands.DiagnosticSuite", _Suite)

    result = runner.invoke(app, ["diagnostics"])
    assert result.exit_code == 0
    assert "Diagnostic Suite" in result.output
    assert "VirusTotal" in result.output


def test_init_creates_starter_config(tmp_path: Path) -> None:
    config_file = tmp_path / "suscheck" / "config.toml"

    result = runner.invoke(app, ["init", "--config-path", str(config_file)])

    assert result.exit_code == 0
    assert config_file.exists()
    content = config_file.read_text(encoding="utf-8")
    assert "[general]" in content
    assert "[risk]" in content


def test_init_is_idempotent(tmp_path: Path) -> None:
    config_file = tmp_path / "suscheck" / "config.toml"
    config_file.parent.mkdir(parents=True, exist_ok=True)
    config_file.write_text("[general]\nverbosity=\"normal\"\n", encoding="utf-8")

    result = runner.invoke(app, ["init", "--config-path", str(config_file)])

    assert result.exit_code == 0
    assert "Config already exists" in result.output


def test_scan_repository_url_runs_temp_clone_path(monkeypatch) -> None:
    class _Proc:
        def __init__(self) -> None:
            self.returncode = 0
            self.stderr = ""

    called = {"clone": False, "scan_directory": False}

    def _fake_run(cmd, capture_output=False, text=False, timeout=None):
        if cmd[:3] == ["git", "clone", "--depth"]:
            called["clone"] = True
        return _Proc()

    def _fake_scan_directory_with_status(self, _target_dir):
        called["scan_directory"] = True
        return type("_DirResult", (), {"findings": [], "modules_ran": [], "modules_failed": []})()

    monkeypatch.setattr("suscheck.services.scan_service.subprocess.run", _fake_run)
    monkeypatch.setattr(
        "suscheck.commands.scan_commands.ScanPipeline.scan_directory_with_status",
        _fake_scan_directory_with_status,
    )

    result = runner.invoke(app, ["scan", "https://github.com/example/repo"])

    assert result.exit_code == 0
    assert called["clone"] is True
    assert called["scan_directory"] is True


def test_scan_package_marks_partial_static_scan(monkeypatch) -> None:
    class _TrustResult:
        def __init__(self) -> None:
            self.error = None
            self.trust_score = 8.5
            self.findings = []

    class _TrustEngine:
        def scan(self, _target):
            return _TrustResult()

    monkeypatch.setattr("suscheck.modules.supply_chain.trust_engine.TrustEngine", _TrustEngine)

    result = runner.invoke(app, ["scan", "requests", "--no-ai"])

    assert result.exit_code == 0
    assert "Tier 1 skipped" in result.output
    assert "manual review" in result.output.lower()
    assert "Modules: supply_chain" in result.output
    assert "Skipped: code" in result.output
    assert "16/100" in result.output


def test_scan_local_file_fans_out_tier1_scanners(monkeypatch, tmp_path: Path) -> None:
    class _Result:
        def __init__(self, findings=None) -> None:
            self.findings = findings or []
            self.skipped_reason = None
            self.error = None
            self.errors = []

    def _finding(module: str, finding_id: str) -> Finding:
        return Finding(
            module=module,
            finding_id=finding_id,
            title=f"{module} finding",
            description="test",
            severity=Severity.LOW,
            finding_type=FindingType.SUSPICIOUS_BEHAVIOR,
            confidence=0.8,
            evidence={},
        )

    called = {"mcp": False, "config": False, "code": False, "repo": False}

    class _Detector:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def detect(self, target: str) -> DetectionResult:
            return DetectionResult(
                artifact_type=ArtifactType.CODE,
                language=Language.PYTHON,
                file_path=Path(target),
                detection_method="test",
                confidence=1.0,
            )

    monkeypatch.setattr("suscheck.commands.scan_commands.AutoDetector", _Detector)

    monkeypatch.setattr("suscheck.services.scan_service.MCPScanner.can_handle", lambda self, _atype, _path: True)
    monkeypatch.setattr(
        "suscheck.services.scan_service.MCPScanner.scan",
        lambda self, _path: called.__setitem__("mcp", True) or _Result([_finding("mcp", "MCP-1")]),
    )

    monkeypatch.setattr("suscheck.services.scan_service.ConfigScanner.can_handle", lambda self, _atype, _path: True)
    monkeypatch.setattr(
        "suscheck.services.scan_service.ConfigScanner.scan",
        lambda self, _path: called.__setitem__("config", True) or _Result([_finding("config", "CFG-1")]),
    )

    monkeypatch.setattr(
        "suscheck.services.scan_service.CodeScanner.scan_file",
        lambda self, _path, language=None: called.__setitem__("code", True) or _Result([_finding("code", "CODE-1")]),
    )

    monkeypatch.setattr(
        "suscheck.services.scan_service.RepoScanner.scan_file_secrets",
        lambda self, _path: called.__setitem__("repo", True) or [_finding("repo", "REPO-1")],
    )

    sample = tmp_path / "sample.py"
    sample.write_text("print('hello')\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(sample), "--no-ai"])

    assert result.exit_code == 0
    assert called["mcp"] is True
    assert called["code"] is True
    assert called["repo"] is True
    assert sum(1 for was_called in called.values() if was_called) >= 3


def test_scan_package_json_report_contains_coverage_contract(monkeypatch, tmp_path: Path) -> None:
    class _TrustResult:
        def __init__(self) -> None:
            self.error = None
            self.trust_score = 8.5
            self.findings = []

    class _TrustEngine:
        def scan(self, _target):
            return _TrustResult()

    monkeypatch.setattr("suscheck.modules.supply_chain.trust_engine.TrustEngine", _TrustEngine)

    report_path = tmp_path / "scan.json"
    result = runner.invoke(
        app,
        ["scan", "requests", "--no-ai", "--format", "json", "--output", str(report_path)],
    )

    assert result.exit_code == 0
    assert report_path.exists()

    payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert payload["coverage_complete"] is False
    assert isinstance(payload["coverage_notes"], list)
    assert any("PIPELINE-PACKAGE-STATIC-SKIPPED" in note for note in payload["coverage_notes"])


def test_scan_mcp_dynamic_failure_is_reported_as_partial(monkeypatch, tmp_path: Path) -> None:
    class _Result:
        def __init__(self, findings=None, error=None) -> None:
            self.findings = findings or []
            self.skipped_reason = None
            self.error = error
            self.errors = []
            self.metadata = {}

    class _Detector:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def detect(self, target: str) -> DetectionResult:
            return DetectionResult(
                artifact_type=ArtifactType.MCP_SERVER,
                language=Language.JSON,
                file_path=Path(target),
                detection_method="test",
                confidence=1.0,
            )

    class _DynResult:
        def __init__(self) -> None:
            self.findings = []
            self.error = "docker unavailable"
            self.metadata = {}

    monkeypatch.setattr("suscheck.commands.scan_commands.AutoDetector", _Detector)
    monkeypatch.setattr("suscheck.services.scan_service.MCPScanner.can_handle", lambda self, *_: True)
    monkeypatch.setattr(
        "suscheck.services.scan_service.MCPScanner.scan",
        lambda self, _path: _Result(
            [
                Finding(
                    module="mcp",
                    finding_id="MCP-1",
                    title="mcp finding",
                    description="test",
                    severity=Severity.LOW,
                    finding_type=FindingType.SUSPICIOUS_BEHAVIOR,
                    confidence=0.8,
                    evidence={},
                )
            ]
        ),
    )
    monkeypatch.setattr("suscheck.commands.scan_commands.MCPDynamicScanner.can_handle", lambda self, *_: True)
    monkeypatch.setattr("suscheck.commands.scan_commands.MCPDynamicScanner.scan", lambda self, _path: _DynResult())

    sample = tmp_path / "mcp.json"
    sample.write_text('{"mcpServers": {"demo": {"command": "node", "args": ["server.js"]}}}', encoding="utf-8")

    report_path = tmp_path / "mcp_scan.json"
    result = runner.invoke(
        app,
        [
            "scan",
            str(sample),
            "--mcp-only",
            "--mcp-dynamic",
            "--no-ai",
            "--no-vt",
            "--format",
            "json",
            "--output",
            str(report_path),
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert "mcp_dynamic" in payload["modules_failed"]
    assert any(f["finding_id"] == "PIPELINE-MCP-DYNAMIC-SKIPPED" for f in payload["findings"])
    assert any("MCP-PHASE-D runtime-dynamic: failed" in note for note in payload["coverage_notes"])


def test_scan_semgrep_failure_adds_partial_finding(monkeypatch, tmp_path: Path) -> None:
    class _Result:
        def __init__(self, findings=None) -> None:
            self.findings = findings or []
            self.skipped_reason = None
            self.error = None
            self.errors = []

    class _Detector:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def detect(self, target: str) -> DetectionResult:
            return DetectionResult(
                artifact_type=ArtifactType.CODE,
                language=Language.PYTHON,
                file_path=Path(target),
                detection_method="test",
                confidence=1.0,
            )

    monkeypatch.setattr("suscheck.commands.scan_commands.AutoDetector", _Detector)
    monkeypatch.setattr("suscheck.services.scan_service.MCPScanner.can_handle", lambda self, *_: False)
    monkeypatch.setattr("suscheck.services.scan_service.ConfigScanner.can_handle", lambda self, *_: False)
    monkeypatch.setattr("suscheck.services.scan_service.CodeScanner.scan_file", lambda self, *_args, **_kwargs: _Result())
    monkeypatch.setattr("suscheck.services.scan_service.RepoScanner.scan_file_secrets", lambda self, _path: [])
    monkeypatch.setattr("suscheck.commands.scan_commands.execute_semgrep_phase", lambda **_kwargs: ([], True))

    sample = tmp_path / "sample.py"
    sample.write_text("print('hello')\n", encoding="utf-8")
    report_path = tmp_path / "scan.json"

    result = runner.invoke(
        app,
        ["scan", str(sample), "--no-ai", "--no-vt", "--format", "json", "--output", str(report_path)],
    )

    assert result.exit_code == 0
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert "semgrep" in payload["modules_failed"]
    assert any(f["finding_id"] == "PIPELINE-SEMGREP-SCAN-SKIPPED" for f in payload["findings"])


def test_scan_directory_depcheck_failure_adds_partial_finding(monkeypatch, tmp_path: Path) -> None:
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
        lambda self, _target: _DirResult(),
    )
    monkeypatch.setattr(
        "suscheck.commands.scan_commands.execute_dependency_check_phase",
        lambda **_kwargs: ([], True),
    )

    report_path = tmp_path / "dir_scan.json"
    result = runner.invoke(
        app,
        [
            "scan",
            str(tmp_path),
            "--dependency-check",
            "--no-ai",
            "--format",
            "json",
            "--output",
            str(report_path),
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert "dependency_check" in payload["modules_failed"]
    assert any(f["finding_id"] == "PIPELINE-DEPENDENCY-CHECK-SKIPPED" for f in payload["findings"])
