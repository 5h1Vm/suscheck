"""Extended tests for the VirusTotal API client."""

import os
from unittest.mock import MagicMock, patch
import pytest
import requests
from suscheck.tier0.virustotal import VirusTotalClient, VirusTotalResult

class MockResponse:
    def __init__(self, json_data, status_code=200):
        self._json = json_data
        self.status_code = status_code
    def json(self): return self._json
    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(f"HTTP {self.status_code}")

def _make_vt_stat_response(malicious=0):
    return {
        "data": {
            "id": "test_id",
            "attributes": {
                "last_analysis_stats": {"malicious": malicious, "suspicious": 0, "undetected": 70},
                "last_analysis_date": 1700000000,
                "tags": []
            }
        }
    }

@pytest.fixture
def mock_session():
    with patch("suscheck.tier0.virustotal.requests.Session") as mock_cls:
        session = MagicMock()
        mock_cls.return_value = session
        yield session

def test_lookup_url_success(mock_session):
    client = VirusTotalClient(api_key="test")
    client._session = mock_session
    mock_session.get.return_value = MockResponse(_make_vt_stat_response(malicious=5))
    
    result = client.lookup_url("http://evil.com")
    assert result is not None
    assert result.detection_count == 5
    assert result.found is True

def test_lookup_ip_success(mock_session):
    client = VirusTotalClient(api_key="test")
    client._session = mock_session
    mock_session.get.return_value = MockResponse(_make_vt_stat_response(malicious=2))
    
    result = client.lookup_ip("8.8.8.8")
    assert result is not None
    assert result.found is True

def test_lookup_domain_success(mock_session):
    client = VirusTotalClient(api_key="test")
    client._session = mock_session
    mock_session.get.return_value = MockResponse(_make_vt_stat_response(malicious=0))
    
    result = client.lookup_domain("google.com")
    assert result is not None
    assert result.detection_count == 0

def test_poll_analysis_completed(mock_session):
    client = VirusTotalClient(api_key="test")
    client._session = mock_session
    
    # First call: status = completed
    mock_session.get.return_value = MockResponse({
        "data": {
            "attributes": {
                "status": "completed",
                "stats": {"malicious": 10, "suspicious": 0, "undetected": 60}
            }
        }
    })
    
    result = client._poll_analysis("analysis_id", "file.py", timeout=10)
    assert result is not None
    assert result.detection_count == 10

def test_make_request_retry_logic(mock_session):
    client = VirusTotalClient(api_key="test")
    client._session = mock_session
    
    # Return 429 then 200
    # Response must contain "data" key as _make_request extracts it
    mock_session.get.side_effect = [
        MockResponse({}, 429),
        MockResponse({"data": {"id": "123"}}, 200)
    ]
    
    with patch("suscheck.tier0.virustotal.time.sleep"):
        res = client._make_request("http://test")
        assert res == {"id": "123"}
        assert mock_session.get.call_count == 2
