"""ScannerModule — Abstract base class for all scanner modules.

Every scanner module (code, supply_chain, repo, mcp, config) must
implement this interface so the pipeline can orchestrate them uniformly.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

from suscheck.core.finding import Finding


@dataclass
class ModuleResult:
    """Standardized result from any scanner module."""
    module_name: str
    findings: list[Finding] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    trust_score: Optional[float] = None   # 0-10, only for supply chain
    scan_duration: float = 0.0
    error: Optional[str] = None


class ScannerModule(ABC):
    """Abstract base class for scanner modules.

    All scanner modules must implement:
      - name: A unique human-readable module name.
      - can_handle(): Whether this module can scan the given artifact.
      - scan(): Execute the scan and return a ModuleResult.

    Usage:
        class MyScanner(ScannerModule):
            @property
            def name(self) -> str:
                return "my_scanner"

            def can_handle(self, artifact_type: str, file_path: str) -> bool:
                return artifact_type == "code"

            def scan(self, target: str, config: dict) -> ModuleResult:
                findings = [...]
                return ModuleResult(module_name=self.name, findings=findings)
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique module identifier (e.g., 'code_scanner', 'supply_chain')."""
        ...

    @abstractmethod
    def can_handle(self, artifact_type: str, file_path: str = "") -> bool:
        """Return True if this module can scan this artifact type.

        Args:
            artifact_type: From AutoDetector (e.g., "code", "config", "package").
            file_path: Path to the file (for extension-based decisions).
        """
        ...

    @abstractmethod
    def scan(self, target: str, config: dict | None = None) -> ModuleResult:
        """Execute the scan.

        Args:
            target: File path, URL, or package name.
            config: Optional configuration overrides.

        Returns:
            ModuleResult with findings, metadata, and timing.
        """
        ...
