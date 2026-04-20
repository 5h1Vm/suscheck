from __future__ import annotations

import requests

from suscheck.core.config_manager import ConfigManager
from suscheck.core.diagnostics import DiagnosticSuite
from suscheck.core.tool_registry import ToolType


def test_virustotal_diagnostic_includes_error_code_on_request_failure(monkeypatch) -> None:
    cfg = ConfigManager()
    monkeypatch.setenv("SUSCHECK_VT_KEY", "dummy-key")

    def _raise(*_args, **_kwargs):
        raise requests.RequestException("network down")

    monkeypatch.setattr("suscheck.core.diagnostics.requests.get", _raise)

    suite = DiagnosticSuite(cfg)
    suite._check_virustotal()

    assert len(suite.results) == 1
    result = suite.results[0]
    assert result.service == "VirusTotal"
    assert result.status == "FAILED"
    assert result.details is not None
    assert result.details.get("error_code") == "DIAG_VIRUSTOTAL_REQUEST_FAILED"


def test_github_diagnostic_includes_error_code_on_request_failure(monkeypatch) -> None:
    cfg = ConfigManager()
    monkeypatch.setenv("SUSCHECK_GITHUB_TOKEN", "dummy-token")

    def _raise(*_args, **_kwargs):
        raise requests.RequestException("timeout")

    monkeypatch.setattr("suscheck.core.diagnostics.requests.get", _raise)

    suite = DiagnosticSuite(cfg)
    suite._check_github()

    assert len(suite.results) == 1
    result = suite.results[0]
    assert result.service == "GitHub"
    assert result.status == "FAILED"
    assert result.details is not None
    assert result.details.get("error_code") == "DIAG_GITHUB_REQUEST_FAILED"


def test_optional_adapters_checked_when_not_installed(monkeypatch) -> None:
    """Test that optional adapters are reported as SKIPPED when not installed."""
    cfg = ConfigManager()
    
    # Mock shutil.which to always return None (adapters not found)
    monkeypatch.setattr("suscheck.core.diagnostics.shutil.which", lambda _: None)
    
    suite = DiagnosticSuite(cfg)
    suite._check_optional_adapters()
    
    # Should have results for all 5 optional adapters
    assert len(suite.results) == 5
    
    # All should be SKIPPED
    for result in suite.results:
        assert "Optional:" in result.service
        assert result.status == "SKIPPED"
        assert "not installed" in result.message.lower()


def test_optional_adapters_detected_when_available(monkeypatch) -> None:
    """Test that optional adapters are reported as OK when installed."""
    cfg = ConfigManager()
    
    # Mock shutil.which to return a fake path
    def mock_which(tool_name):
        return f"/usr/local/bin/{tool_name}"
    
    monkeypatch.setattr("suscheck.core.diagnostics.shutil.which", mock_which)
    
    # Mock subprocess.run for version checks
    import subprocess
    class MockResult:
        stdout = "nuclei v2.9.0"
        stderr = ""
    
    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: MockResult())
    
    suite = DiagnosticSuite(cfg)
    suite._check_optional_adapters()
    
    # Should have results for all 5 optional adapters
    assert len(suite.results) == 5
    
    # All should be OK
    for result in suite.results:
        assert "Optional:" in result.service
        assert result.status == "OK"
        assert "/usr/local/bin/" in result.message
