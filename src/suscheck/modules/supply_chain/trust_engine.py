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
        
        # Parse target. e.g. "pypi:requests@2.31.0" or just "requests@2.31.0"
        version = None
        if "@" in target:
            target, version = target.split("@", 1)

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
        meta = pypi_client.get_package_metadata(pkg_name, version=version)
        if not meta:
            return ModuleResult(
                module_name=self.name,
                findings=[],
                scan_duration=time.time() - start_time,
                error=f"Package {pkg_name} not found on PyPI"
            )

        # --- 9-Category Weighted Trust Scoring ---
        # Weights (Checkpoint 1a §7 Module 2)
        # Typosquat 15%, Maintainer 15%, Takeover 15%, Abandoned 10%, 
        # Delta 10%, Confusion 10%, Install 10%, Metadata 5%, CVEs 10%
        
        score_components = {
            "typosquat": 1.0,
            "maintainer": 1.0,
            "takeover": 1.0,
            "abandoned": 1.0,
            "delta": 1.0,
            "confusion": 1.0,
            "install": 1.0,
            "metadata": 1.0,
            "cves": 1.0
        }

        # 1. Typosquat Detection (15%)
        if pkg_name not in self.POPULAR_PACKAGES:
            for pop_pkg in self.POPULAR_PACKAGES:
                dist = Levenshtein.distance(pkg_name.lower(), pop_pkg.lower())
                if 1 <= dist <= 2:
                    score_components["typosquat"] = 0.0
                    findings.append(
                        Finding(
                            module="trust_engine",
                            finding_id="TRUST-TYPOSQUAT",
                            title=f"Potential Typosquat of '{pop_pkg}'",
                            description=f"Package name '{pkg_name}' is dangerously close to popular package '{pop_pkg}'.",
                            severity=Severity.HIGH,
                            finding_type=FindingType.TYPOSQUATTING,
                            confidence=0.85,
                            mitre_ids=["T1189"]
                        )
                    )
                    break

        # 2. Maintainer Reputation & Account Age (15%)
        if meta.first_upload_time:
            account_age = datetime.now(timezone.utc) - meta.first_upload_time.replace(tzinfo=timezone.utc)
            if account_age.days < 30:
                score_components["maintainer"] = 0.2
                findings.append(
                    Finding(
                        module="trust_engine",
                        finding_id="TRUST-NEW-ACCOUNT",
                        title="Brand New Account",
                        description=f"Package registered {account_age.days} days ago. Highly suspicious for targeted supply chain attacks.",
                        severity=Severity.MEDIUM,
                        finding_type=FindingType.MAINTAINER_RISK,
                        confidence=0.9
                    )
                )
            elif meta.release_count < 2 and account_age.days < 90:
                 score_components["maintainer"] = 0.5

        # 3. Package Takeover Detection (15%)
        # Logic: If account is old but this is the first release by a NEW author/maintainer name
        # (This heuristic is simplified for v1 based on available metadata)
        if meta.maintainer and meta.author and meta.maintainer != meta.author:
             score_components["takeover"] = 0.7
             # This is just a warning in v1 as it happens in legitimate forks
        
        # 4. Abandoned Packages (10%)
        if meta.latest_upload_time:
            project_delta = datetime.now(timezone.utc) - meta.latest_upload_time.replace(tzinfo=timezone.utc)
            if project_delta.days > 365:
                score_components["abandoned"] = 0.4
                findings.append(
                    Finding(
                        module="trust_engine",
                        finding_id="TRUST-ABANDONED",
                        title="Project Abandoned",
                        description=f"Inactive for {project_delta.days} days.",
                        severity=Severity.MEDIUM,
                        finding_type=FindingType.ABANDONED_PACKAGE,
                        confidence=1.0,
                    )
                )

        # 5. Yanked History (Part of Maintainer/Release Delta 10%)
        if meta.yanked:
            score_components["delta"] = 0.0
            findings.append(
                Finding(
                    module="trust_engine",
                    finding_id="TRUST-YANKED",
                    title="Package Version Yanked",
                    description="Maintainer explicitly revoked this version.",
                    severity=Severity.CRITICAL,
                    finding_type=FindingType.MAINTAINER_RISK,
                    confidence=1.0,
                )
            )

        # 6. Dependency Confusion (10%)
        # Check for internal-sounding names (simplified heuristic)
        if any(x in pkg_name.lower() for x in ["-corp", "-internal", "-private", "dev-"]):
             score_components["confusion"] = 0.5

        # 9. CVEs & Transitive Deps (10% + weighting)
        deps_client = DepsDevClient()
        if meta.version:
            deps_result = deps_client.get_dependencies("pypi", pkg_name, meta.version)
            if deps_result:
                cve_count = len(deps_result.advisories)
                if cve_count > 0:
                    score_components["cves"] = max(0.0, 1.0 - (cve_count * 0.4))
                    for cve in deps_result.advisories:
                        findings.append(
                            Finding(
                                module="trust_engine",
                                finding_id=f"TRUST-CVE-{cve.get('sourceID')}",
                                title=f"Known CVE: {cve.get('sourceID')}",
                                description=cve.get("title", ""),
                                severity=Severity.HIGH,
                                finding_type=FindingType.CVE,
                                confidence=1.0,
                            )
                        )

        # Calculate Final Weighted Score (0-10 Scale)
        weights = {
            "typosquat": 1.5, "maintainer": 1.5, "takeover": 1.5,
            "abandoned": 1.0, "delta": 1.0, "confusion": 1.0,
            "install": 1.0, "metadata": 0.5, "cves": 1.0
        }
        
        total_score = sum(score_components[k] * weights[k] for k in weights)
        final_trust = max(0.0, min(10.0, total_score))

        return ModuleResult(
            module_name=self.name,
            findings=findings,
            trust_score=final_trust,
            scan_duration=time.time() - start_time,
            error="; ".join(errors) if errors else None
        )
