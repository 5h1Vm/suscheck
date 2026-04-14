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

    def _extract_cvss_score(self, advisory: dict) -> float | None:
        """Best-effort CVSS extraction from deps.dev advisory payloads."""
        candidates = [
            advisory.get("cvss"),
            advisory.get("cvssScore"),
            advisory.get("severityScore"),
        ]
        for value in candidates:
            if isinstance(value, (int, float)):
                return float(value)
            if isinstance(value, str):
                try:
                    return float(value)
                except ValueError:
                    continue
        return None

    def _severity_for_advisory(self, advisory: dict, advisory_type: str, path_depth: int) -> Severity:
        """Map advisory impact using CVSS first, then depth-aware defaults."""
        cvss = self._extract_cvss_score(advisory)
        if cvss is not None:
            if cvss >= 9.0:
                return Severity.CRITICAL
            if cvss >= 7.0:
                return Severity.HIGH
            if cvss >= 4.0:
                return Severity.MEDIUM
            return Severity.LOW

        if advisory_type == "TRANSITIVE" and path_depth >= 3:
            return Severity.MEDIUM
        return Severity.HIGH

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
        score_components = {
            "typosquat": 1.0, "maintainer": 1.0, "takeover": 1.0,
            "abandoned": 1.0, "delta": 1.0, "confusion": 1.0,
            "install": 1.0, "metadata": 1.0, "cves": 1.0
        }
        account_age = None
        
        # 1. Typosquat Detection (15%) - Run BEFORE metadata lookup
        # Catch dangerous names even if they don't exist yet on PyPI
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

        # 1.5 Fetch PyPI Metadata
        pypi_client = PyPIClient()
        meta = pypi_client.get_package_metadata(pkg_name, version=version)
        if not meta:
            # If package doesn't exist, we still return whatever findings (like typosquat) we have
            return ModuleResult(
                module_name=self.name,
                findings=findings,
                trust_score=5.0 if findings else 10.0, # Neutral if unknown but looks safe
                scan_duration=time.time() - start_time,
                error=None if findings else f"Package {pkg_name} not found on PyPI"
            )

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
        # Heuristic: If account is old but this is the first release by a NEW author/maintainer name
        # OR if author and maintainer are different and account age is relatively low (< 1 year)
        if meta.maintainer and meta.author and meta.maintainer != meta.author:
             is_recent_pkg = account_age and account_age.days < 365
             if is_recent_pkg:
                score_components["takeover"] = 0.4
                findings.append(
                    Finding(
                        module="trust_engine",
                        finding_id="TRUST-TAKEOVER-MISMATCH",
                        title="Author/Maintainer Mismatch",
                        description=f"Package author ({meta.author}) differs from maintainer ({meta.maintainer}) on a relatively new package. Possible takeover or credential sharing.",
                        severity=Severity.MEDIUM,
                        finding_type=FindingType.TAKEOVER,
                        confidence=0.65
                    )
                )
             else:
                score_components["takeover"] = 0.8

        # 3b. Release Cadence Anomaly (Supplement for Takeover)
        if meta.release_count > 5 and account_age and account_age.days > 0:
            cadence = meta.release_count / (account_age.days / 30) # releases per month
            if cadence > 10 and account_age.days < 180:
                score_components["takeover"] = min(score_components["takeover"], 0.3)
                findings.append(
                    Finding(
                        module="trust_engine",
                        finding_id="TRUST-HIGH-CADENCE",
                        title="Abnormal Release Cadence",
                        description=f"Package has {meta.release_count} releases in {account_age.days} days ({cadence:.1f}/mo). Sudden spikes in releases often precede malicious payload injection.",
                        severity=Severity.MEDIUM,
                        finding_type=FindingType.TAKEOVER,
                        confidence=0.75
                    )
                )
        
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
             findings.append(
                Finding(
                    module="trust_engine",
                    finding_id="TRUST-CONFUSION",
                    title="Potential Dependency Confusion Name",
                    description=f"Package name '{pkg_name}' contains internal/private patterns. Verify it's not a hijacked internal namespace.",
                    severity=Severity.LOW,
                    finding_type=FindingType.DEPENDENCY_CONFUSION,
                    confidence=0.6
                )
             )

        # 7. Install Script Risk (10%)
        # Check for suspicious strings in summary/description if available
        # (v1 approximation using metadata descriptions where available)
        desc = (str(meta.home_page or "") + str(meta.project_urls or {})).lower()
        suspicious_markers = ["curl", "wget", "chmod", "os.system", "subprocess", "eval(", "exec("]
        if any(sm in desc for sm in suspicious_markers):
            score_components["install"] = 0.3
            findings.append(
                Finding(
                    module="trust_engine",
                    finding_id="TRUST-SCRIPT-RISK",
                    title="Suspicious Metadata Instructions",
                    description="Package metadata references shell tools or dynamic execution. May indicate malicious install scripts.",
                    severity=Severity.HIGH,
                    finding_type=FindingType.INSTALL_SCRIPT_RISK,
                    confidence=0.7
                )
            )

        metadata_findings = []
        hp = (meta.home_page or "").lower()
        if hp and not hp.startswith("https://"):
            if "localhost" not in hp and "127.0.0.1" not in hp:
                metadata_findings.append("Non-HTTPS homepage")
        if not meta.author_email or "@" not in meta.author_email:
            metadata_findings.append("Invalid/Missing author email")
        
        if metadata_findings:
            score_components["metadata"] = 0.5
            findings.append(
                Finding(
                    module="trust_engine",
                    finding_id="TRUST-METADATA-HYGIENE",
                    title="Poor Metadata Hygiene",
                    description=f"Package metadata has quality issues: {', '.join(metadata_findings)}.",
                    severity=Severity.LOW,
                    finding_type=FindingType.METADATA_MISMATCH,
                    confidence=0.8
                )
            )

        # 9. CVEs & Transitive Deps (10% + weighting)
        deps_client = DepsDevClient()
        if meta.version:
            deps_result = deps_client.get_dependencies("pypi", pkg_name, meta.version)
            if deps_result:
                # Build simple adjacency map for path reconstruction
                adj = {}
                for edge in deps_result.edges:
                    src = edge.get("fromNode")
                    dst = edge.get("toNode")
                    if src not in adj: adj[src] = []
                    adj[src].append(dst)
                
                def get_path_to(target_idx: int) -> str:
                    # Simple BFS to find path from root (usually node 0) to target
                    import collections
                    q = collections.deque([(0, [0])])
                    visited = {0}
                    while q:
                        curr, path = q.popleft()
                        if curr == target_idx:
                            return " -> ".join([deps_result.dependencies[i].package_name for i in path])
                        for neighbor in adj.get(curr, []):
                            if neighbor not in visited:
                                visited.add(neighbor)
                                q.append((neighbor, path + [neighbor]))
                    return "unknown path"

                # 9. CVEs & Transitive Deps (10% + weighting)
                advisories_found = []
                seen_adv_keys = set()

                # Root package advisories from dependency API response.
                for adv in deps_result.advisories or []:
                    adv_key = f"root::{adv.get('sourceID') or adv.get('id') or repr(adv)}"
                    if adv_key in seen_adv_keys:
                        continue
                    seen_adv_keys.add(adv_key)
                    advisories_found.append(
                        {
                            "cve": adv,
                            "path": pkg_name,
                            "type": "DIRECT",
                            "depth": 1,
                        }
                    )

                # Expand to dependency nodes (direct + transitive) with capped lookups.
                max_nodes = 30
                nodes_scanned = 0
                for dep in deps_result.dependencies:
                    if dep.package_name == pkg_name:
                        continue
                    if dep.version in {"", "unknown", None}:
                        continue
                    if nodes_scanned >= max_nodes:
                        break

                    dep_advisories = deps_client.get_advisories("pypi", dep.package_name, dep.version)
                    nodes_scanned += 1
                    if not dep_advisories:
                        continue

                    path = get_path_to(dep.node_id)
                    depth = len(path.split(" -> ")) if path != "unknown path" else 0
                    adv_type = "DIRECT" if dep.is_direct else "TRANSITIVE"
                    for adv in dep_advisories:
                        adv_identifier = adv.get("sourceID") or adv.get("id") or repr(adv)
                        adv_key = f"{dep.package_name}@{dep.version}::{adv_identifier}"
                        if adv_key in seen_adv_keys:
                            continue
                        seen_adv_keys.add(adv_key)
                        advisories_found.append(
                            {
                                "cve": adv,
                                "path": path,
                                "type": adv_type,
                                "depth": depth,
                                "package": dep.package_name,
                                "version": dep.version,
                            }
                        )

                cve_count = len(advisories_found)
                if cve_count > 0:
                    score_components["cves"] = max(0.0, 1.0 - (cve_count * 0.4))
                    for adv_item in advisories_found:
                        cve = adv_item["cve"]
                        path = adv_item["path"]
                        adv_type = adv_item["type"]
                        path_depth = adv_item.get("depth", 0)
                        severity = self._severity_for_advisory(cve, adv_type, path_depth)
                        
                        finding_title = f"Known CVE: {cve.get('sourceID')}"
                        finding_desc = cve.get("title", "Stability/Security vulnerability")
                        
                        # Forensic Chain Reconstruction (Checkpoint 1a Section 8)
                        finding_desc = (
                            f"Vulnerability chain ({adv_type}, depth {path_depth}): {path}\n"
                            f"Details: {finding_desc}"
                        )
                            
                        findings.append(
                            Finding(
                                module="trust_engine",
                                finding_id=f"TRUST-CVE-{cve.get('sourceID')}",
                                title=finding_title,
                                description=finding_desc,
                                severity=severity,
                                finding_type=FindingType.CVE,
                                confidence=1.0,
                                evidence={
                                    "transitive_path": path,
                                    "advisory_type": adv_type,
                                    "path_depth": path_depth,
                                    "package": adv_item.get("package", pkg_name),
                                    "version": adv_item.get("version", meta.version),
                                    "cve_id": cve.get('sourceID'),
                                    "cvss": cve.get('cvss')
                                }
                            )
                        )

                if nodes_scanned >= max_nodes and len(deps_result.dependencies) > max_nodes:
                    findings.append(
                        Finding(
                            module="trust_engine",
                            finding_id="TRUST-TRANSITIVE-SCAN-CAPPED",
                            title="Transitive advisory lookup capped",
                            description=(
                                f"Scanned {max_nodes} dependency nodes out of "
                                f"{len(deps_result.dependencies)} to control lookup cost."
                            ),
                            severity=Severity.LOW,
                            finding_type=FindingType.REVIEW_NEEDED,
                            confidence=0.9,
                            evidence={"scanned_nodes": max_nodes, "total_nodes": len(deps_result.dependencies)},
                            needs_human_review=True,
                            review_reason="Partial transitive advisory lookup due to lookup cap",
                        )
                    )
                
                # Signal depth of transitive mapping
                if deps_result.dependencies:
                    depth = 0
                    if deps_result.edges:
                        # Estimate depth from edge structure
                        depth = max([len(get_path_to(i).split(" -> ")) for i in range(len(deps_result.dependencies))] or [0])
                    
                    findings.append(
                        Finding(
                            module="trust_engine",
                            finding_id="TRUST-TRANSITIVE-INDEX",
                            title=f"Indexed {len(deps_result.dependencies)} transitive dependencies",
                            description=f"Dependency graph analyzed. Root package chain depth: {depth} levels.",
                            severity=Severity.INFO,
                            finding_type=FindingType.TRANSITIVE_DEPENDENCY,
                            confidence=1.0,
                            evidence={
                                "dependency_count": len(deps_result.dependencies),
                                "max_depth": depth,
                                "advisory_nodes_scanned": nodes_scanned,
                            }
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
