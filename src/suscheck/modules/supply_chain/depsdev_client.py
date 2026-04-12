"""Deps.dev API Client for mapping transitive dependencies and vulnerabilities."""

import logging
from dataclasses import dataclass
from typing import Optional

import requests

logger = logging.getLogger(__name__)


@dataclass
class DependencyNode:
    """A node inside the transitive dependency tree."""
    package_name: str
    version: str
    is_direct: bool
    relation: str
    node_id: int  # Added to track index for path reconstruction

@dataclass
class DepsDevResult:
    """Transitive dependency tree and metadata from Deps.dev."""
    dependencies: list[DependencyNode]
    advisories: list[dict]  # Known CVEs mapped in this version
    edges: list[dict]      # Relationships between nodes


class DepsDevClient:
    """Client for querying the Google deps.dev OSV Engine."""

    BASE_URL = "https://api.deps.dev/v3"

    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "SusCheck/0.1.0 (Security Scanner)",
        })

    def get_dependencies(self, system: str, package_name: str, version: str) -> Optional[DepsDevResult]:
        """Fetch the fully resolved transitive dependency tree and advisories."""
        # Endpoint: /v3/systems/{system}/packages/{name}/versions/{version}/dependencies
        url = f"{self.BASE_URL}/systems/{system}/packages/{package_name}/versions/{version}/dependencies"
        
        try:
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code != 200:
                logger.debug(f"Deps.dev API returned {resp.status_code} for {package_name}@{version}")
                return None

            data = resp.json()
            nodes = data.get("nodes", [])
            edges = data.get("edges", [])

            # Rebuild a flat list of dependency nodes for scanning
            dependencies = []
            for i, node in enumerate(nodes):
                n_key = node.get("versionKey", {})
                dependencies.append(DependencyNode(
                    package_name=n_key.get("name", "unknown"),
                    version=n_key.get("version", "unknown"),
                    is_direct=node.get("relation") == "DIRECT",
                    relation=node.get("relation", "UNKNOWN"),
                    node_id=i
                ))

            # Fetch security advisories specifically for this package version
            advisories = self._get_advisories(system, package_name, version)

            return DepsDevResult(
                dependencies=dependencies,
                advisories=advisories,
                edges=edges
            )
        except Exception as e:
            logger.debug(f"Deps.dev fetch failed: {e}")
            return None

    def _get_advisories(self, system: str, package_name: str, version: str) -> list[dict]:
        """Fetch OSV security advisories for a specific package version."""
        url = f"{self.BASE_URL}/systems/{system}/packages/{package_name}/versions/{version}"
        try:
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("advisories", [])
        except Exception:
            pass
        return []
