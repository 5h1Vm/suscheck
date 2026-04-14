from __future__ import annotations

from datetime import datetime, timedelta, timezone

from suscheck.modules.supply_chain.depsdev_client import DependencyNode, DepsDevResult
from suscheck.modules.supply_chain.pypi_client import PyPIMetadata
from suscheck.modules.supply_chain.trust_engine import TrustEngine
from suscheck.core.finding import Severity


def _stable_metadata(name: str = "demo") -> PyPIMetadata:
    now = datetime.now(timezone.utc)
    return PyPIMetadata(
        name=name,
        version="1.0.0",
        author="alice",
        author_email="alice@example.com",
        maintainer="alice",
        home_page="https://example.com",
        project_urls={"Source": "https://example.com/repo"},
        yanked=False,
        upload_time=now - timedelta(days=200),
        latest_version="1.0.0",
        latest_upload_time=now - timedelta(days=30),
        first_upload_time=now - timedelta(days=200),
        release_count=4,
        size=12345,
    )


def test_trust_engine_surfaces_transitive_advisory_with_path(monkeypatch) -> None:
    deps_result = DepsDevResult(
        dependencies=[
            DependencyNode("demo", "1.0.0", True, "SELF", 0),
            DependencyNode("dep-a", "2.0.0", True, "DIRECT", 1),
            DependencyNode("dep-b", "3.0.0", False, "TRANSITIVE", 2),
        ],
        advisories=[],
        edges=[
            {"fromNode": 0, "toNode": 1},
            {"fromNode": 1, "toNode": 2},
        ],
    )

    monkeypatch.setattr(
        "suscheck.modules.supply_chain.pypi_client.PyPIClient.get_package_metadata",
        lambda self, pkg_name, version=None: _stable_metadata(pkg_name),
    )
    monkeypatch.setattr(
        "suscheck.modules.supply_chain.depsdev_client.DepsDevClient.get_dependencies",
        lambda self, system, package_name, version: deps_result,
    )

    def _fake_get_advisories(self, system, package_name, version):
        if package_name == "dep-b":
            return [{"sourceID": "CVE-2099-0001", "title": "transitive vuln", "cvss": "8.2"}]
        return []

    monkeypatch.setattr(
        "suscheck.modules.supply_chain.depsdev_client.DepsDevClient.get_advisories",
        _fake_get_advisories,
    )

    result = TrustEngine().scan("pypi:demo")

    cve_findings = [f for f in result.findings if f.finding_type.value == "cve"]
    assert cve_findings, "expected at least one CVE finding"

    transitive = next(f for f in cve_findings if f.evidence.get("advisory_type") == "TRANSITIVE")
    assert transitive.evidence.get("transitive_path") == "demo -> dep-a -> dep-b"
    assert transitive.evidence.get("path_depth") == 3
    assert transitive.severity == Severity.HIGH


def test_trust_engine_depth_policy_for_missing_cvss(monkeypatch) -> None:
    deps_result = DepsDevResult(
        dependencies=[
            DependencyNode("demo", "1.0.0", True, "SELF", 0),
            DependencyNode("dep-a", "2.0.0", True, "DIRECT", 1),
            DependencyNode("dep-b", "3.0.0", False, "TRANSITIVE", 2),
            DependencyNode("dep-c", "4.0.0", False, "TRANSITIVE", 3),
        ],
        advisories=[],
        edges=[
            {"fromNode": 0, "toNode": 1},
            {"fromNode": 1, "toNode": 2},
            {"fromNode": 2, "toNode": 3},
        ],
    )

    monkeypatch.setattr(
        "suscheck.modules.supply_chain.pypi_client.PyPIClient.get_package_metadata",
        lambda self, pkg_name, version=None: _stable_metadata(pkg_name),
    )
    monkeypatch.setattr(
        "suscheck.modules.supply_chain.depsdev_client.DepsDevClient.get_dependencies",
        lambda self, system, package_name, version: deps_result,
    )

    def _fake_get_advisories(self, system, package_name, version):
        if package_name == "dep-c":
            return [{"sourceID": "CVE-2099-0002", "title": "no cvss present"}]
        return []

    monkeypatch.setattr(
        "suscheck.modules.supply_chain.depsdev_client.DepsDevClient.get_advisories",
        _fake_get_advisories,
    )

    result = TrustEngine().scan("pypi:demo")

    cve_findings = [f for f in result.findings if f.finding_id == "TRUST-CVE-CVE-2099-0002"]
    assert len(cve_findings) == 1
    assert cve_findings[0].evidence.get("path_depth") == 4
    assert cve_findings[0].severity == Severity.MEDIUM
