from __future__ import annotations

import requests

from suscheck.core.config_manager import ConfigManager
from suscheck.core.diagnostics import DiagnosticSuite


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
