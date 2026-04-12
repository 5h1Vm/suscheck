"""Tests for graceful degradation during network and API failures."""

import pytest
from unittest.mock import patch, MagicMock
import requests
from suscheck.tier0.virustotal import VirusTotalClient
from suscheck.tier0.abuseipdb import AbuseIPDBClient

@patch("requests.get")
def test_vt_network_error_graceful(mock_get):
    """Ensure VirusTotal client handles network timeouts without crashing."""
    mock_get.side_effect = requests.exceptions.ReadTimeout("Timeout")
    client = VirusTotalClient(api_key="test")
    
    # VirusTotal returns a Result with found=False on network timeout
    result = client.lookup_hash("e" * 64)
    assert result is not None
    assert result.found is False

@patch("requests.get")
def test_abuseipdb_429_graceful(mock_get):
    """Ensure AbuseIPDB handles rate limits gracefully."""
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_get.return_value = mock_resp
    
    client = AbuseIPDBClient(api_key="test")
    result = client.lookup_ip("1.2.3.4")
    assert result is None

@patch("suscheck.ai.factory.create_ai_provider")
@patch("suscheck.ai.factory.get_available_providers")
def test_ai_triage_fail_open(mock_get_av, mock_create):
    """Ensure the scan continues even if AI triage fails completely."""
    from suscheck.ai.triage_engine import run_ai_triage
    from suscheck.core.finding import Finding, Severity, FindingType
    
    # Mock only one provider available
    mock_get_av.return_value = ["mock_fail"]
    
    mock_provider = MagicMock()
    mock_provider.name = "mock_fail"
    mock_provider.is_configured.return_value = True
    mock_provider.complete_triage_json.side_effect = Exception("API Down")
    
    # Ensure create_ai_provider returns our failing mock
    mock_create.return_value = mock_provider
    
    findings = [Finding(module="m", finding_id="id", title="t", description="d", severity=Severity.INFO, finding_type=FindingType.REVIEW_NEEDED, confidence=1.0)]
    
    # Should return a result with 'ran=False', but NOT crash
    result = run_ai_triage(findings, target="test.py", artifact_type="code")
    assert result.ran is False
    assert result.error is not None
    # We don't check the exact error string since rotation might change it
