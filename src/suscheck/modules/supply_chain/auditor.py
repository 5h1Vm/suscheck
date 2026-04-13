"""Supply Chain Auditor.

Detects dependency manifest files (requirements.txt, pyproject.toml)
and runs a full supply chain trust audit on all entries.
"""

import logging
import os
import re
from typing import List

from suscheck.core.finding import Finding, FindingType, Severity
from suscheck.modules.supply_chain.trust_engine import TrustEngine

logger = logging.getLogger(__name__)

class SupplyChainAuditor:
    """Orchestrates bulk dependency auditing for repositories."""

    def __init__(self):
        self.trust_engine = TrustEngine()

    def scan_manifest(self, file_path: str) -> List[Finding]:
        """Parse a dependency file and scan each package."""
        findings = []
        
        filename = os.path.basename(file_path).lower()
        
        packages = []
        if filename == "requirements.txt":
            packages = self._parse_requirements(file_path)
        elif filename == "pyproject.toml":
            packages = self._parse_pyproject(file_path)
            
        if not packages:
            return []

        logger.info(f"Auditing {len(packages)} dependencies from {filename}")
        
        for pkg in packages:
            try:
                # Format: ecosystem:pkg_name@version (used by TrustEngine)
                target = f"pypi:{pkg}"
                result = self.trust_engine.scan(target)
                findings.extend(result.findings)
            except Exception as e:
                logger.debug(f"Failed to audit package {pkg}: {e}")
                
        return findings

    def _parse_requirements(self, file_path: str) -> List[str]:
        """Extract packages from a requirements.txt file."""
        packages = []
        try:
            with open(file_path, "r") as f:
                for line in f:
                    line = line.strip()
                    # Skip comments and empty lines
                    if not line or line.startswith("#"):
                        continue
                    # Simplify: extract name before ==, >=, etc.
                    # Example: requests==2.31.0 -> requests@2.31.0
                    match = re.match(r'^([a-zA-Z0-9_\-\[\]]+)([=><!~]+[0-9.a-zA-Z*\-\+]+)?', line)
                    if match:
                        name = match.group(1)
                        version_part = match.group(2)
                        if version_part:
                            # Strip symbols like ==, >= to get just the version
                            version = re.sub(r'^[=><!~]+', '', version_part)
                            packages.append(f"{name}@{version}")
                        else:
                            packages.append(name)
        except Exception as e:
            logger.error(f"Failed to parse requirements.txt: {e}")
            
        return packages

    def _parse_pyproject(self, file_path: str) -> List[str]:
        """Extract packages from pyproject.toml."""
        # Simple regex-based extraction for v1 to avoid adding toml dependencies
        packages = []
        try:
            with open(file_path, "r") as f:
                content = f.read()
                # Find the dependencies section
                deps_match = re.search(r'dependencies\s*=\s*\[(.*?)\]', content, re.DOTALL)
                if deps_match:
                    deps_block = deps_match.group(1)
                    # Extract strings inside the list
                    items = re.findall(r'"([^"]+)"', deps_block)
                    for item in items:
                        # item format: "requests>=2.31.0"
                        match = re.match(r'^([a-zA-Z0-9_\-\[\]]+)([=><!~]+[0-9.a-zA-Z*\-\+]+)?', item)
                        if match:
                            name = match.group(1)
                            version_part = match.group(2)
                            if version_part:
                                version = re.sub(r'^[=><!~]+', '', version_part)
                                packages.append(f"{name}@{version}")
                            else:
                                packages.append(name)
        except Exception as e:
            logger.error(f"Failed to parse pyproject.toml: {e}")
            
        return packages
