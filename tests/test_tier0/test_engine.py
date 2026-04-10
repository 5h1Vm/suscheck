"""Tests for the Tier 0 Engine (orchestration + short-circuit logic)."""

import os
from unittest.mock import MagicMock, patch

import pytest

from suscheck.core.finding import FindingType, Severity
from suscheck.tier0.engine import Tier0Engine, Tier0Result
from suscheck.tier0.hash_engine import HashResult
from suscheck.tier0.virustotal import VirusTotalResult


SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "samples", "benign")


class TestTier0Result:
    """Test the Tier0Result dataclass."""

    def test_vt_dict_none_when_no_vt(self):
        result = Tier0Result()
        assert result.vt_dict is None

    def test_vt_dict_returns_dict_when_vt_present(self):
        vt = VirusTotalResult(
            hash_sha256="abc", detection_count=5, total_engines=70, found=True
        )
        result = Tier0Result(vt_result=vt)
        d = result.vt_dict
        assert d is not None
        assert d["detection_count"] == 5

    def test_defaults(self):
        result = Tier0Result()
        assert result.short_circuit is False
        assert result.findings == []
        assert result.pri_adjustment == 0
        assert result.errors == []


class TestTier0EngineHashing:
    """Test Tier 0 Engine hash computation (no VT)."""

    def setup_method(self):
        # Create engine with no VT key so VT is skipped
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("SUSCHECK_VT_KEY", None)
            self.engine = Tier0Engine(vt_api_key=None)

    def test_check_file_computes_hashes(self):
        """check_file should compute SHA-256, MD5, SHA-1."""
        hello_path = os.path.join(SAMPLES_DIR, "hello.py")
        result = self.engine.check_file(hello_path)

        assert result.hash_result is not None
        assert len(result.hash_result.sha256) == 64  # SHA-256 hex length
        assert len(result.hash_result.md5) == 32     # MD5 hex length
        assert len(result.hash_result.sha1) == 40    # SHA-1 hex length
        assert result.hash_result.file_size > 0

    def test_check_file_no_vt(self):
        """Without VT key, vt_result should be None."""
        hello_path = os.path.join(SAMPLES_DIR, "hello.py")
        result = self.engine.check_file(hello_path)

        assert result.vt_result is None
        assert result.short_circuit is False

    def test_check_file_missing_file(self):
        """Missing file should produce error, not crash."""
        result = self.engine.check_file("/nonexistent/file.py")

        assert result.hash_result is None
        assert len(result.errors) > 0
        assert "not found" in result.errors[0].lower() or "Hash computation failed" in result.errors[0]

    def test_check_file_records_duration(self):
        """Scan duration should be recorded."""
        hello_path = os.path.join(SAMPLES_DIR, "hello.py")
        result = self.engine.check_file(hello_path)

        assert result.scan_duration >= 0

    def test_check_bytes(self):
        """check_bytes should compute hashes for raw bytes."""
        data = b"test data for hashing"
        result = self.engine.check_bytes(data, label="test-payload")

        assert result.hash_result is not None
        assert result.hash_result.file_size == len(data)
        assert result.hash_result.file_path == "test-payload"


class TestTier0EngineVTIntegration:
    """Test Tier 0 Engine VirusTotal integration (mocked)."""

    def _make_engine_with_mock_vt(self):
        """Create engine with a mocked VT client."""
        engine = Tier0Engine(vt_api_key="test-key")
        engine.vt_client = MagicMock()
        engine.vt_client.available = True
        return engine

    def test_clean_file_negative_pri(self):
        """Clean file (0 detections) should give -5 PRI adjustment."""
        engine = self._make_engine_with_mock_vt()
        engine.vt_client.lookup_hash.return_value = VirusTotalResult(
            hash_sha256="abc" * 16,
            detection_count=0,
            total_engines=70,
            found=True,
            vt_link="https://virustotal.com/gui/file/abc",
        )

        hello_path = os.path.join(SAMPLES_DIR, "hello.py")
        result = engine.check_file(hello_path)

        assert result.pri_adjustment == -5
        assert result.short_circuit is False
        assert len(result.findings) == 1
        assert result.findings[0].finding_id == "VT-CLEAN-001"

    def test_low_detections_medium_severity(self):
        """1-3 detections should produce MEDIUM finding."""
        engine = self._make_engine_with_mock_vt()
        engine.vt_client.lookup_hash.return_value = VirusTotalResult(
            hash_sha256="abc" * 16,
            detection_count=2,
            total_engines=70,
            detection_names=["Kaspersky: Generic.Malware"],
            found=True,
            malicious=True,
            vt_link="https://virustotal.com/gui/file/abc",
        )

        hello_path = os.path.join(SAMPLES_DIR, "hello.py")
        result = engine.check_file(hello_path)

        assert result.pri_adjustment == 10
        assert result.short_circuit is False
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.MEDIUM
        assert result.findings[0].needs_human_review is True

    def test_moderate_detections_high_severity(self):
        """4-10 detections should produce HIGH finding."""
        engine = self._make_engine_with_mock_vt()
        engine.vt_client.lookup_hash.return_value = VirusTotalResult(
            hash_sha256="abc" * 16,
            detection_count=7,
            total_engines=70,
            found=True,
            malicious=True,
            vt_link="https://virustotal.com/gui/file/abc",
        )

        hello_path = os.path.join(SAMPLES_DIR, "hello.py")
        result = engine.check_file(hello_path)

        assert result.pri_adjustment == 25
        assert result.short_circuit is False
        assert result.findings[0].severity == Severity.HIGH

    def test_high_detections_critical_severity(self):
        """11-25 detections should produce CRITICAL finding."""
        engine = self._make_engine_with_mock_vt()
        engine.vt_client.lookup_hash.return_value = VirusTotalResult(
            hash_sha256="abc" * 16,
            detection_count=15,
            total_engines=70,
            found=True,
            malicious=True,
            vt_link="https://virustotal.com/gui/file/abc",
        )

        hello_path = os.path.join(SAMPLES_DIR, "hello.py")
        result = engine.check_file(hello_path)

        assert result.pri_adjustment == 40
        assert result.short_circuit is False
        assert result.findings[0].severity == Severity.CRITICAL

    def test_confirmed_malicious_short_circuit(self):
        """26+ detections should trigger short-circuit."""
        engine = self._make_engine_with_mock_vt()
        engine.vt_client.lookup_hash.return_value = VirusTotalResult(
            hash_sha256="dead" * 16,
            detection_count=45,
            total_engines=70,
            detection_names=["Kaspersky: Trojan.Win32", "Avast: Win32:Malware"],
            found=True,
            malicious=True,
            vt_link="https://virustotal.com/gui/file/dead",
            suggested_threat_label="trojan.generic",
            tags=["peexe"],
        )

        hello_path = os.path.join(SAMPLES_DIR, "hello.py")
        result = engine.check_file(hello_path)

        assert result.short_circuit is True
        assert result.pri_adjustment == 60
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.CRITICAL
        assert result.findings[0].confidence == 0.99
        assert result.findings[0].finding_id == "VT-MALICIOUS-001"
        assert "SHORT-CIRCUITED" in result.findings[0].description

    def test_hash_not_found_info_finding(self):
        """Hash not in VT should produce INFO finding with REVIEW flag."""
        engine = self._make_engine_with_mock_vt()
        engine.vt_client.lookup_hash.return_value = VirusTotalResult(
            hash_sha256="unknown" * 8,
            detection_count=0,
            total_engines=0,
            found=False,
        )

        hello_path = os.path.join(SAMPLES_DIR, "hello.py")
        result = engine.check_file(hello_path)

        assert result.short_circuit is False
        assert result.pri_adjustment == 0
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.INFO
        assert result.findings[0].needs_human_review is True
        assert result.findings[0].finding_id == "VT-NOTFOUND-001"

    def test_vt_returns_none_no_findings(self):
        """When VT client returns None (error), no findings from VT."""
        engine = self._make_engine_with_mock_vt()
        engine.vt_client.lookup_hash.return_value = None

        hello_path = os.path.join(SAMPLES_DIR, "hello.py")
        result = engine.check_file(hello_path)

        assert result.vt_result is None
        assert result.short_circuit is False
        assert result.findings == []

    def test_findings_have_mitre_ids(self):
        """Malicious findings should include MITRE ATT&CK IDs."""
        engine = self._make_engine_with_mock_vt()
        engine.vt_client.lookup_hash.return_value = VirusTotalResult(
            hash_sha256="abc" * 16,
            detection_count=30,
            total_engines=70,
            found=True,
            malicious=True,
            vt_link="https://virustotal.com/gui/file/abc",
        )

        hello_path = os.path.join(SAMPLES_DIR, "hello.py")
        result = engine.check_file(hello_path)

        assert result.findings[0].mitre_ids
        assert "T1588.001" in result.findings[0].mitre_ids

    def test_findings_have_evidence(self):
        """All findings should include evidence dict."""
        engine = self._make_engine_with_mock_vt()
        engine.vt_client.lookup_hash.return_value = VirusTotalResult(
            hash_sha256="abc" * 16,
            detection_count=10,
            total_engines=70,
            found=True,
            malicious=True,
            vt_link="https://virustotal.com/gui/file/abc",
        )

        hello_path = os.path.join(SAMPLES_DIR, "hello.py")
        result = engine.check_file(hello_path)

        evidence = result.findings[0].evidence
        assert "vt_link" in evidence
        assert "detection_count" in evidence
        assert "total_engines" in evidence
