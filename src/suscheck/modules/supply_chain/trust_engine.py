"""Supply Chain Trust Engine.

Evaluates trust signals like Typosquatting, Abandonment, and Transitive Risks
to calculate a final 0-10 Trust Score.
"""

import time
from datetime import datetime, timezone
import Levenshtein

from suscheck.core.finding import Finding, FindingType, Severity
from suscheck.modules.base import ModuleResult, ScannerModule
from suscheck.modules.supply_chain.pypi_client import PyPIClient
from suscheck.modules.supply_chain.depsdev_client import DepsDevClient


class TrustEngine(ScannerModule):
    """Calculates supply chain health signals for a package."""

    # Hand-mapped list of high-value targets for typosquatting checks
    POPULAR_PACKAGES = {
        "requests", "urllib3", "numpy", "pandas", "flask", 
        "django", "fastapi", "pytest", "boto3", "botocore",
        "matplotlib", "scipy", "scikit-learn", "tensorflow", "pytorch"
    }

    @property
    def name(self) -> str:
        return "supply_chain"

    def can_handle(self, artifact_type: str, file_path: str = "") -> bool:
        """Handle package names targeted for dynamic supply chain checks."""
        return artifact_type == "package"

    def scan(self, target: str, config: dict | None = None) -> ModuleResult:
        """Execute the Trust API requests. target is assumed to be ecosystem/pkg."""
        start_time = time.time()
        findings = []
        errors = []
        
        # Parse target. e.g. "pypi:requests" or just "requests" (defaults to pypi)
        if ":" in target:
            ecosystem, pkg_name = target.split(":", 1)
        else:
            ecosystem, pkg_name = "pypi", target
            
        ecosystem = ecosystem.lower()
        if ecosystem != "pypi":
            return ModuleResult(
                module_name=self.name, 
                findings=[], 
                scan_duration=time.time() - start_time,
                error=f"Ecosystem {ecosystem} not supported yet in v1. Available: pypi"
            )

        trust_score = 10.0  # Start fully trusted
        
        # 1. Fetch PyPI Metadata
        pypi_client = PyPIClient()
        meta = pypi_client.get_package_metadata(pkg_name)
        if not meta:
            return ModuleResult(
                module_name=self.name,
                findings=[],
                scan_duration=time.time() - start_time,
                error=f"Package {pkg_name} not found on PyPI"
            )

        # Signal 1: Typosquatting
        if pkg_name not in self.POPULAR_PACKAGES:
            for pop_pkg in self.POPULAR_PACKAGES:
                dist = Levenshtein.distance(pkg_name.lower(), pop_pkg.lower())
                # If distance is extremely small (e.g. 1 or 2 edits away)
                if 1 <= dist <= 2:
                    trust_score -= 3.0
                    findings.append(
                        Finding(
                            module="trust_engine",
                            finding_id="TRUST-TYPOSQUAT",
                            title=f"Potential Typosquat of '{pop_pkg}'",
                            description=f"Package name '{pkg_name}' is dangerously close to popular package '{pop_pkg}'. Check spelling.",
                            severity=Severity.HIGH,
                            finding_type=FindingType.TYPOSQUATTING,
                            confidence=0.85,
                            mitre_ids=["T1189"]
                        )
                    )
                    break

        # Signal 2: Abandoned packages
        if meta.upload_time:
            delta = datetime.now(timezone.utc) - meta.upload_time.replace(tzinfo=timezone.utc)
            if delta.days > 365:
                trust_score -= 2.0
                findings.append(
                    Finding(
                        module="trust_engine",
                        finding_id="TRUST-ABANDONED",
                        title=f"Package Abandoned (>1 year)",
                        description=f"The latest version was uploaded {delta.days} days ago. Ensure it is still maintained.",
                        severity=Severity.MEDIUM,
                        finding_type=FindingType.ABANDONED_PACKAGE,
                        confidence=1.0,
                        mitre_ids=["T1195.002"]
                    )
                )

        # Signal 3: Yanked Package
        if meta.yanked:
            trust_score -= 5.0
            findings.append(
                Finding(
                    module="trust_engine",
                    finding_id="TRUST-YANKED",
                    title="Package Version Yanked",
                    description="The maintainer explicitly yanked this version from PyPI.",
                    severity=Severity.CRITICAL,
                    finding_type=FindingType.MAINTAINER_RISK,
                    confidence=1.0,
                )
            )

        # 2. Fetch deps.dev SCA (Software Composition Analysis)
        deps_client = DepsDevClient()
        # Ensure we have a valid version to pass to deps.dev
        if meta.version:
            deps_result = deps_client.get_dependencies("pypi", pkg_name, meta.version)
            if deps_result:
                # Map CVEs found in this exact package
                for cve in deps_result.advisories:
                    cve_id = cve.get("sourceID") or "UNKNOWN-CVE"
                    trust_score -= 4.0
                    findings.append(
                        Finding(
                            module="trust_engine",
                            finding_id=f"TRUST-CVE-{cve_id}",
                            title=f"Known Vulnerability: {cve_id}",
                            description=cve.get("title", f"Package has known CVE advisory: {cve_id}"),
                            severity=Severity.HIGH,
                            finding_type=FindingType.CVE,
                            confidence=1.0,
                        )
                    )
        
        # Clamp Trust Score
        final_trust = max(0.0, min(10.0, trust_score))

        return ModuleResult(
            module_name=self.name,
            findings=findings,
            trust_score=final_trust,
            scan_duration=time.time() - start_time,
            error="; ".join(errors) if errors else None
        )
