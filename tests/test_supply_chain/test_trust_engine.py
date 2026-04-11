"""Tests for the Supply Chain Trust Engine."""

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone, timedelta

from suscheck.modules.supply_chain.trust_engine import TrustEngine
from suscheck.modules.supply_chain.pypi_client import PyPIMetadata
from suscheck.core.finding import FindingType, Severity


@pytest.fixture
def trust_engine():
    return TrustEngine()


@patch("suscheck.modules.supply_chain.trust_engine.PyPIClient")
@patch("suscheck.modules.supply_chain.trust_engine.DepsDevClient")
def test_clean_package(mock_deps_cls, mock_pypi_cls, trust_engine):
    """Test a perfectly clean and trusted package."""
    mock_pypi = mock_pypi_cls.return_value
    mock_deps = mock_deps_cls.return_value
    
    # Mock PyPI returning a recent update
    mock_pypi.get_package_metadata.return_value = PyPIMetadata(
        name="requests",
        version="2.31.0",
        author="Kenneth",
        author_email="test@test.com",
        maintainer="Kenneth",
        home_page="http",
        project_urls={},
        yanked=False,
        upload_time=datetime.now(timezone.utc) - timedelta(days=10),
        size=1000
    )
    
    # Mock deps.dev returning 0 CVEs
    mock_deps_result = MagicMock()
    mock_deps_result.advisories = []
    mock_deps.get_dependencies.return_value = mock_deps_result

    res = trust_engine.scan("requests")
    assert res.error is None
    assert res.trust_score == 10.0
    assert len(res.findings) == 0


@patch("suscheck.modules.supply_chain.trust_engine.PyPIClient")
@patch("suscheck.modules.supply_chain.trust_engine.DepsDevClient")
def test_typosquatting_and_abandoned(mock_deps_cls, mock_pypi_cls, trust_engine):
    """Test a package that is typosquatted (requesrs) and abandoned (> 2 years)."""
    mock_pypi = mock_pypi_cls.return_value
    mock_deps = mock_deps_cls.return_value
    
    mock_pypi.get_package_metadata.return_value = PyPIMetadata(
        name="requesrs",
        version="1.0.0",
        author="Evil",
        author_email="evil@evil.com",
        maintainer="Evil",
        home_page="",
        project_urls={},
        yanked=False,
        upload_time=datetime.now(timezone.utc) - timedelta(days=800), # > 365 days
        size=500
    )
    
    mock_deps_result = MagicMock()
    mock_deps_result.advisories = []
    mock_deps.get_dependencies.return_value = mock_deps_result

    res = trust_engine.scan("requesrs")
    
    assert res.error is None
    # 10.0 base - 3.0 (Typosquat) - 2.0 (Abandoned) = 5.0
    assert res.trust_score == 5.0
    assert len(res.findings) == 2
    
    typo = next(f for f in res.findings if f.finding_type == FindingType.TYPOSQUATTING)
    assert typo.severity == Severity.HIGH
    
    abandoned = next(f for f in res.findings if f.finding_type == FindingType.ABANDONED_PACKAGE)
    assert abandoned.severity == Severity.MEDIUM


@patch("suscheck.modules.supply_chain.trust_engine.PyPIClient")
@patch("suscheck.modules.supply_chain.trust_engine.DepsDevClient")
def test_cve_advisories(mock_deps_cls, mock_pypi_cls, trust_engine):
    """Test CVE deduction from deps.dev."""
    mock_pypi = mock_pypi_cls.return_value
    mock_deps = mock_deps_cls.return_value
    
    mock_pypi.get_package_metadata.return_value = PyPIMetadata(
        name="some-pkg",
        version="1.0.0",
        author="Test",
        author_email="",
        maintainer="",
        home_page="",
        project_urls={},
        yanked=False,
        upload_time=datetime.now(timezone.utc),
        size=500
    )
    
    mock_deps_result = MagicMock()
    mock_deps_result.advisories = [
        {"sourceID": "CVE-2024-1234", "title": "RCE in some-pkg"},
        {"sourceID": "GHSA-5678", "title": "XSS in some-pkg"}
    ]
    mock_deps.get_dependencies.return_value = mock_deps_result

    res = trust_engine.scan("some-pkg")
    
    # Base 10 - 4.0 - 4.0 = 2.0
    assert res.trust_score == 2.0
    assert len(res.findings) == 2
    for f in res.findings:
        assert f.finding_type == FindingType.CVE
        assert f.severity == Severity.HIGH
