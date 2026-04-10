"""Tests for the VirusTotal API client (with mocked API responses)."""

import os
from unittest.mock import MagicMock, patch

import pytest

from suscheck.tier0.virustotal import VirusTotalClient, VirusTotalResult


# ── Mock responses ────────────────────────────────────────────

def _make_vt_file_response(
    sha256: str = "abc123" * 8,
    malicious: int = 0,
    suspicious: int = 0,
    undetected: int = 70,
    detection_names: dict | None = None,
    tags: list | None = None,
    threat_label: str | None = None,
):
    """Build a mock VT /files/ API response."""
    results = {}
    if detection_names:
        for engine, name in detection_names.items():
            results[engine] = {"category": "malicious", "result": name}

    attrs = {
        "sha256": sha256,
        "last_analysis_stats": {
            "malicious": malicious,
            "suspicious": suspicious,
            "undetected": undetected,
            "harmless": 0,
            "timeout": 0,
            "type-unsupported": 0,
            "failure": 0,
            "confirmed-timeout": 0,
        },
        "last_analysis_results": results,
        "last_analysis_date": 1700000000,
        "tags": tags or [],
    }

    if threat_label:
        attrs["popular_threat_classification"] = {
            "suggested_threat_label": threat_label,
        }

    return {"data": {"attributes": attrs}}


class MockResponse:
    """Mock requests.Response."""

    def __init__(self, json_data, status_code=200):
        self._json = json_data
        self.status_code = status_code

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            from requests.exceptions import HTTPError
            raise HTTPError(f"HTTP {self.status_code}")


# ── Tests ─────────────────────────────────────────────────────

class TestVirusTotalResultModel:
    """Test the VirusTotalResult dataclass."""

    def test_to_dict(self):
        result = VirusTotalResult(
            hash_sha256="abc",
            detection_count=5,
            total_engines=70,
            detection_names=["Trojan.Generic"],
            malicious=True,
            vt_link="https://virustotal.com/gui/file/abc",
            found=True,
        )
        d = result.to_dict()
        assert d["hash_sha256"] == "abc"
        assert d["detection_count"] == 5
        assert d["found"] is True
        assert d["malicious"] is True

    def test_defaults(self):
        result = VirusTotalResult(
            hash_sha256="abc", detection_count=0, total_engines=0
        )
        assert result.malicious is False
        assert result.found is False
        assert result.detection_names == []
        assert result.tags == []
        assert result.suggested_threat_label is None


class TestVirusTotalClient:
    """Test the VirusTotal API client with mocked responses."""

    def test_no_api_key_returns_unavailable(self):
        """Client without API key should not be available."""
        with patch.dict(os.environ, {}, clear=True):
            # Make sure env var is not set
            os.environ.pop("SUSCHECK_VT_KEY", None)
            client = VirusTotalClient(api_key=None)
            assert client.available is False

    def test_api_key_from_constructor(self):
        """Client should accept API key from constructor."""
        client = VirusTotalClient(api_key="test-key-123")
        assert client.available is True

    def test_no_key_lookup_returns_none(self):
        """Lookup without API key should return None."""
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("SUSCHECK_VT_KEY", None)
            client = VirusTotalClient(api_key=None)
            result = client.lookup_hash("abc123")
            assert result is None

    @patch("suscheck.tier0.virustotal.requests.Session")
    def test_lookup_hash_clean_file(self, mock_session_cls):
        """Test lookup of a clean file (0 detections)."""
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        response_data = _make_vt_file_response(malicious=0, undetected=70)
        mock_session.get.return_value = MockResponse(response_data, 200)

        client = VirusTotalClient(api_key="test-key")
        client._session = mock_session

        result = client.lookup_hash("abc123" * 8)

        assert result is not None
        assert result.found is True
        assert result.detection_count == 0
        assert result.malicious is False
        assert result.total_engines == 70

    @patch("suscheck.tier0.virustotal.requests.Session")
    def test_lookup_hash_malicious_file(self, mock_session_cls):
        """Test lookup of a malicious file (high detections)."""
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        response_data = _make_vt_file_response(
            malicious=45,
            suspicious=3,
            undetected=22,
            detection_names={
                "Kaspersky": "Trojan.Win32.Generic",
                "Avast": "Win32:Malware-gen",
            },
            threat_label="trojan.generic",
            tags=["peexe", "signed"],
        )
        mock_session.get.return_value = MockResponse(response_data, 200)

        client = VirusTotalClient(api_key="test-key")
        client._session = mock_session

        result = client.lookup_hash("deadbeef" * 8)

        assert result is not None
        assert result.found is True
        assert result.detection_count == 48  # 45 malicious + 3 suspicious
        assert result.malicious is True
        assert result.total_engines == 70
        assert result.suggested_threat_label == "trojan.generic"
        assert len(result.detection_names) == 2

    @patch("suscheck.tier0.virustotal.requests.Session")
    def test_lookup_hash_not_found(self, mock_session_cls):
        """Test lookup when hash is not in VT database."""
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        mock_session.get.return_value = MockResponse({}, 404)

        client = VirusTotalClient(api_key="test-key")
        client._session = mock_session

        result = client.lookup_hash("notfound" * 8)

        assert result is not None
        assert result.found is False
        assert result.detection_count == 0

    @patch("suscheck.tier0.virustotal.requests.Session")
    def test_lookup_hash_rate_limited(self, mock_session_cls):
        """Test that rate limiting triggers retry then skip."""
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        # Return 429 both times
        mock_session.get.return_value = MockResponse({}, 429)

        client = VirusTotalClient(api_key="test-key")
        client._session = mock_session

        # Patch sleep to avoid waiting 15s in tests
        with patch("suscheck.tier0.virustotal.time.sleep"):
            result = client.lookup_hash("ratelimited" * 4)

        # Should return not-found result
        assert result is not None
        assert result.found is False

    @patch("suscheck.tier0.virustotal.requests.Session")
    def test_lookup_hash_auth_error(self, mock_session_cls):
        """Test that 401/403 returns None."""
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        mock_session.get.return_value = MockResponse({}, 401)

        client = VirusTotalClient(api_key="bad-key")
        client._session = mock_session

        result = client.lookup_hash("abc123" * 8)

        # Auth error → None → should return not-found result
        assert result is not None
        assert result.found is False

    @patch("suscheck.tier0.virustotal.requests.Session")
    def test_lookup_hash_network_error(self, mock_session_cls):
        """Test graceful handling of network errors."""
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        from requests.exceptions import ConnectionError
        mock_session.get.side_effect = ConnectionError("No network")

        client = VirusTotalClient(api_key="test-key")
        client._session = mock_session

        result = client.lookup_hash("abc123" * 8)

        # Network error → None → should return not-found result
        assert result is not None
        assert result.found is False

    @patch("suscheck.tier0.virustotal.requests.Session")
    def test_lookup_hash_timeout(self, mock_session_cls):
        """Test graceful handling of request timeouts."""
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        from requests.exceptions import Timeout
        mock_session.get.side_effect = Timeout("Request timed out")

        client = VirusTotalClient(api_key="test-key")
        client._session = mock_session

        result = client.lookup_hash("abc123" * 8)

        assert result is not None
        assert result.found is False

    def test_lookup_url_no_key(self):
        """URL lookup without key returns None."""
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("SUSCHECK_VT_KEY", None)
            client = VirusTotalClient(api_key=None)
            result = client.lookup_url("https://evil.com")
            assert result is None

    def test_lookup_ip_no_key(self):
        """IP lookup without key returns None."""
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("SUSCHECK_VT_KEY", None)
            client = VirusTotalClient(api_key=None)
            result = client.lookup_ip("1.2.3.4")
            assert result is None

    def test_lookup_domain_no_key(self):
        """Domain lookup without key returns None."""
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("SUSCHECK_VT_KEY", None)
            client = VirusTotalClient(api_key=None)
            result = client.lookup_domain("evil.com")
            assert result is None
