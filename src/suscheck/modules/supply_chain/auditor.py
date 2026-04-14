"""Supply Chain Auditor.

Detects dependency manifest files (requirements.txt, pyproject.toml)
and runs a full supply chain trust audit on all entries.
"""

import logging
import os
import re
from typing import List

from suscheck.core.finding import Finding
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

    def scan_source_imports(self, file_path: str) -> List[Finding]:
        """Audit dependencies extracted directly from source code imports."""
        findings = []
        ext = os.path.splitext(file_path)[1].lower()
        
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return []

        raw_candidates = set()
        if ext == ".py":
            # 1. 'from x ...' -> x
            matches = re.finditer(r'^\s*from\s+([a-zA-Z0-9_\-]+)', content, re.MULTILINE)
            for m in matches:
                pkg = m.group(1).strip()
                raw_candidates.add(pkg)
            # 2. 'import x' -> x
            # Stop at end of line or comment
            matches = re.finditer(r'^\s*import\s+([^#\n\r]+)', content, re.MULTILINE)
            for m in matches:
                # Handle comma-separated imports: import os, sys, requests
                pkg_line = m.group(1).strip()
                parts = pkg_line.split(",")
                for p in parts:
                    # pkg as alias: import requests as r
                    p_clean = p.strip()
                    if " as " in p_clean:
                        p_clean = p_clean.split(" as ")[0].strip()
                    clean = p_clean.split(".")[0].strip()
                    if clean:
                        raw_candidates.add(clean)

        elif ext in (".js", ".ts", ".jsx", ".tsx"):
            # require('x')
            # import x from 'y'
            matches = re.finditer(r'require\s*\(\s*["\']([^"\']+)["\']\s*\)', content)
            for m in matches:
                raw_candidates.add(m.group(1).strip())
            matches = re.finditer(r'from\s+["\']([^"\']+)["\']', content)
            for m in matches:
                raw_candidates.add(m.group(1).strip())

        logger.debug(f"Source Auditor raw candidates in {file_path}: {raw_candidates}")

        ecosystem = "pypi" if ext == ".py" else "npm"
        packages = set()
        for raw in raw_candidates:
            normalized = self._normalize_import_candidate(raw, ecosystem)
            if normalized:
                packages.add(normalized)
            else:
                logger.debug("Rejected malformed package candidate from source import: %r", raw)

        logger.debug(f"Source Auditor normalized candidates in {file_path}: {packages}")

        # Filter out built-ins (simple v1 list)
        builtins = {"os", "sys", "time", "re", "json", "math", "random", "fs", "path", "http", "stream", "crypto"}
        packages = [p for p in packages if p and p not in builtins]

        for pkg in packages:
            try:
                # Check for typosquatting and trust on the extracted name
                result = self.trust_engine.scan(f"{ecosystem}:{pkg}")
                
                # Tag these as Shadow Dependencies
                for f in result.findings:
                    f.description = f"[SHADOW DEP] Found in code imports: {f.description}"
                    f.file_path = file_path # Contextualize for Aggregator
                    findings.append(f)
            except Exception:
                continue
        
        return findings

    def _normalize_import_candidate(self, raw: str, ecosystem: str) -> str | None:
        """Normalize source import token into a safe package candidate."""
        token = (raw or "").strip().strip("\"'")
        if not token:
            return None

        if ecosystem == "npm":
            token = token.split("?", 1)[0].split("#", 1)[0].strip()
            if token.startswith("@"):
                parts = [p for p in token.split("/") if p]
                if len(parts) < 2:
                    return None
                token = f"@{parts[0].lstrip('@')}/{parts[1]}"
                npm_pattern = r"^@[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*$"
            else:
                token = token.split("/", 1)[0]
                npm_pattern = r"^[a-z0-9][a-z0-9._-]*$"
            return token if re.match(npm_pattern, token, re.IGNORECASE) else None

        # pypi/python import candidates should be simple top-level names.
        token = token.split(".", 1)[0]
        if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$", token):
            return None
        return token

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
