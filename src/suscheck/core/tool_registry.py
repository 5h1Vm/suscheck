"""Production-ready tool validation and registry.

CRITICAL FOR PRODUCTION:
- Pre-validate all external tools before scanning
- Provide clear installation guidance
- No "command not found" errors during scan
- Unified tool resolution (PATH or config override)
"""

import logging
import shutil
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional, Dict

logger = logging.getLogger(__name__)


class ToolType(str, Enum):
    """External tools SusCheck depends on."""
    SEMGREP = "semgrep"
    GITLEAKS = "gitleaks"
    BANDIT = "bandit"
    CHECKOV = "checkov"
    KICS = "kics"
    GIT = "git"


TOOL_INSTALLATION_URLS: Dict[ToolType, str] = {
    ToolType.SEMGREP: "https://semgrep.dev/install/",
    ToolType.GITLEAKS: "https://github.com/gitleaks/gitleaks#installation",
    ToolType.BANDIT: "https://github.com/PyCQA/bandit#setup-and-installation",
    ToolType.CHECKOV: "https://www.checkov.io/",
    ToolType.KICS: "https://docs.kicsinfra.com/gitbook/getting-started/installation",
    ToolType.GIT: "https://git-scm.com/download",
}


@dataclass
class ToolStatus:
    """Status of a single external tool."""
    tool: ToolType
    available: bool
    path: Optional[str] = None
    error: Optional[str] = None
    suggestion: Optional[str] = None


class ToolRegistry:
    """Central registry for all external tools - single source of truth.
    
    Benefits:
    - Pre-flight validation before scan starts
    - Consistent tool resolution
    - Clear error messages with installation guidance
    - Config overrides with fallback to PATH
    """

    def __init__(self):
        self._tools: Dict[ToolType, Optional[str]] = {}
        self._cached_status: Dict[ToolType, ToolStatus] = {}

    def register_tool(
        self,
        tool: ToolType,
        config_path: Optional[str] = None,
    ) -> ToolStatus:
        """Register a tool and validate availability.
        
        Args:
            tool: Tool to register
            config_path: Optional explicit path from config
            
        Returns:
            ToolStatus with availability and details
        """
        if tool in self._cached_status:
            return self._cached_status[tool]

        # Try explicit config path first
        if config_path:
            path = Path(config_path)
            if path.exists() and path.is_file():
                self._tools[tool] = str(path)
                status = ToolStatus(tool=tool, available=True, path=str(path))
                self._cached_status[tool] = status
                logger.debug(f"Tool {tool.value} registered from config: {path}")
                return status
            else:
                error = f"Config path does not exist: {config_path}"
                logger.warning(f"Tool {tool.value}: {error}")

        # Fall back to PATH
        path = shutil.which(tool.value)
        if path:
            self._tools[tool] = path
            status = ToolStatus(tool=tool, available=True, path=path)
            self._cached_status[tool] = status
            logger.debug(f"Tool {tool.value} found in PATH: {path}")
            return status

        # Fall back to sibling binary near current interpreter (e.g. .venv/bin)
        interp_dir = Path(sys.executable).resolve().parent
        sibling = interp_dir / tool.value
        if sibling.exists() and sibling.is_file():
            self._tools[tool] = str(sibling)
            status = ToolStatus(tool=tool, available=True, path=str(sibling))
            self._cached_status[tool] = status
            logger.debug(f"Tool {tool.value} found near interpreter: {sibling}")
            return status

        # KICS supports Docker fallback when local binary is unavailable.
        if tool is ToolType.KICS:
            docker_path = shutil.which("docker")
            if docker_path:
                status = ToolStatus(
                    tool=tool,
                    available=True,
                    path="docker://checkmarx/kics:latest",
                )
                self._cached_status[tool] = status
                logger.debug("Tool kics available via Docker fallback")
                return status

        # Not found - provide guidance
        install_url = TOOL_INSTALLATION_URLS.get(tool, "")
        error = f"Tool not found in PATH: {tool.value}"
        suggestion = f"Install from: {install_url}" if install_url else ""

        status = ToolStatus(
            tool=tool,
            available=False,
            error=error,
            suggestion=suggestion,
        )
        self._cached_status[tool] = status
        logger.warning(f"Tool {tool.value} not available: {error}")
        return status

    def get_tool_path(self, tool: ToolType) -> str:
        """Get path to tool, raising if not available.
        
        Args:
            tool: Tool to get
            
        Returns:
            Path to tool executable
            
        Raises:
            FileNotFoundError: If tool not registered or not found
        """
        status = self.register_tool(tool)
        if not status.available:
            msg = status.error or f"Tool not available: {tool.value}"
            if status.suggestion:
                msg += f"\n  {status.suggestion}"
            raise FileNotFoundError(msg)
        return status.path

    def validate_tools(self, tools: list[ToolType]) -> tuple[list[ToolStatus], list[str]]:
        """Validate multiple tools at once.
        
        Args:
            tools: List of tools to validate
            
        Returns:
            (list of ToolStatus, list of missing tool names)
        """
        statuses = []
        missing = []

        for tool in tools:
            status = self.register_tool(tool)
            statuses.append(status)
            if not status.available:
                missing.append(tool.value)

        return statuses, missing

    def diagnostic_report(self) -> str:
        """Generate human-readable diagnostic report for all tools."""
        lines = ["=== External Tools Status ===\n"]

        for tool in ToolType:
            status = self.register_tool(tool)
            if status.available:
                lines.append(f"  ✓ {tool.value:<20} {status.path}")
            else:
                lines.append(f"  ✗ {tool.value:<20} NOT FOUND")
                if status.suggestion:
                    lines.append(f"    → {status.suggestion}")

        return "\n".join(lines)


# Global singleton registry
_registry: Optional[ToolRegistry] = None


def get_tool_registry() -> ToolRegistry:
    """Get or create global tool registry."""
    global _registry
    if _registry is None:
        _registry = ToolRegistry()
    return _registry


def reset_tool_registry() -> None:
    """Reset global registry (mainly for testing)."""
    global _registry
    _registry = None
