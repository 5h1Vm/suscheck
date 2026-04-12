"""Tests for the AbuseIPDB client."""

from unittest.mock import patch, MagicMock

import pytest

from suscheck.tier0.abuseipdb import AbuseIPDBClient, AbuseIPDBResult
from suscheck.core.finding import Finding, FindingType, Severity


class TestAbuseIPDBClient:
    def test_no_api_key_skips(self):
        client = AbuseIPDBClient(api_key=None)
        # Force is_configured to False in case env vars are set locally
        client.is_configured = False
        assert client.lookup_ip("8.8.8.8") is None

    @patch("suscheck.tier0.abuseipdb.requests.get")
    def test_lookup_ip_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "ipAddress": "8.8.8.8",
                "abuseConfidenceScore": 100,
                "totalReports": 50,
                "countryCode": "US",
                "domain": "google.com",
                "isPublic": True,
                "isWhitelisted": False
            }
        }
        mock_get.return_value = mock_response

        client = AbuseIPDBClient(api_key="dummy")
        result = client.lookup_ip("8.8.8.8")
        
        assert result is not None
        assert result.ip_address == "8.8.8.8"
        assert result.abuse_confidence_score == 100
        assert result.total_reports == 50
        assert result.country_code == "US"
        assert result.domain == "google.com"

    @patch("suscheck.tier0.abuseipdb.requests.get")
    def test_lookup_ip_rate_limited(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_get.return_value = mock_response

        client = AbuseIPDBClient(api_key="dummy")
        result = client.lookup_ip("1.2.3.4")
        assert result is None

    @patch("suscheck.tier0.abuseipdb.requests.get")
    def test_lookup_ip_invalid_key(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_get.return_value = mock_response

        client = AbuseIPDBClient(api_key="dummy")
        result = client.lookup_ip("1.2.3.4")
        assert result is None

    @patch("suscheck.tier0.abuseipdb.requests.get")
    def test_lookup_ip_network_error(self, mock_get):
        import requests
        mock_get.side_effect = requests.RequestException("Connection error")

        client = AbuseIPDBClient(api_key="dummy")
        result = client.lookup_ip("1.2.3.4")
        assert result is None

    def test_create_finding_clean(self):
        result = AbuseIPDBResult(
            ipAddress="8.8.8.8",
            abuseConfidenceScore=0,
            totalReports=0,
            isPublic=True
        )
        client = AbuseIPDBClient(api_key="dummy")
        finding = client.create_finding(result)
        assert finding is None

    def test_create_finding_malicious(self):
        result = AbuseIPDBResult(
            ipAddress="1.2.3.4",
            abuseConfidenceScore=90,
            totalReports=100,
            isPublic=True,
            countryCode="XX",
            domain="evil.com",
            isWhitelisted=False
        )
        client = AbuseIPDBClient(api_key="dummy")
        finding = client.create_finding(result)
        
        assert finding is not None
        assert finding.severity == Severity.CRITICAL
        assert finding.finding_type == FindingType.C2_INDICATOR
        assert "1.2.3.4" in finding.title
        assert "XX" in finding.description
        assert "evil.com" in finding.description
        assert finding.evidence["abuse_score"] == 90
        assert finding.evidence["total_reports"] == 100

    def test_create_finding_medium_severity(self):
        result = AbuseIPDBResult(
            ipAddress="1.2.3.4",
            abuseConfidenceScore=30,
            totalReports=5,
            isPublic=True
        )
        client = AbuseIPDBClient(api_key="dummy")
        finding = client.create_finding(result)
        assert finding is not None
        assert finding.severity == Severity.MEDIUM
