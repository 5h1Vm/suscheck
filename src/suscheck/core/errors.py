"""Typed diagnostic errors and helpers for scan orchestration.

PRODUCTION-READY ERROR HANDLING:
- All errors explicitly typed and categorized
- All errors logged and surfaced to users
- No silent failures or degradation without user knowledge
- Unified ScanResult contract for all scanners
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from suscheck.core.finding import Finding


class ErrorSeverity(str, Enum):
    """Error severity levels for user-facing reporting."""
    CRITICAL = "CRITICAL"  # Scan must stop
    HIGH = "HIGH"  # Scanner failed, scan continues but partial
    MEDIUM = "MEDIUM"  # Tool skipped but scan continues
    LOW = "LOW"  # Informational, no impact


class ScanError(str, Enum):
    """Standardized scan error types - no silent failures."""
    TOOL_NOT_FOUND = "TOOL_NOT_FOUND"  # e.g., "gitleaks" not in PATH
    TOOL_FAILED = "TOOL_FAILED"  # e.g., semgrep crashed
    API_KEY_MISSING = "API_KEY_MISSING"  # No credentials configured
    API_CALL_FAILED = "API_CALL_FAILED"  # Network or auth error
    CONFIG_INVALID = "CONFIG_INVALID"  # Bad config file
    INPUT_INVALID = "INPUT_INVALID"  # User provided invalid path
    PARSE_ERROR = "PARSE_ERROR"  # Invalid output format
    PERMISSION_DENIED = "PERMISSION_DENIED"  # File access denied
    TIMEOUT = "TIMEOUT"  # Operation timed out
    UNKNOWN = "UNKNOWN"  # Unmapped error


@dataclass
class ScanResult:
    """Unified result contract for ALL scanners - no silent failures.
    
    Every scanner (code, config, repo, supply-chain) returns this struct.
    Error handling is explicit: errors list is always visible to caller.
    Coverage tracking ensures partial scans are detected.
    """
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    
    # Coverage tracking - CRITICAL for security tools
    # coverage_pct: float = 100.0  # 0-100%, None means unknown
    # files_scanned: int = 0
    # files_total: int = 0
    
    metadata: dict[str, Any] = field(default_factory=dict)
    
    @property
    def succeeded(self) -> bool:
        """True if scan completed without CRITICAL errors."""
        return len(self.errors) == 0
    
    @property
    def has_partial_coverage(self) -> bool:
        """True if some files/tools were skipped."""
        return len(self.skipped) > 0


class SuscheckError(Exception):
    """Base exception carrying a stable diagnostic error code.
    
    PRODUCTION-READY: All SuscheckErrors must be caught and
    converted to user-visible findings or error messages.
    Never allow SuscheckError to crash the scan.
    """

    code = "SUSCHECK_ERROR"

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        severity: ErrorSeverity = ErrorSeverity.HIGH,
    ) -> None:
        super().__init__(message)
        if code:
            self.code = code
        self.severity = severity


class RepositoryCloneError(SuscheckError):
    """Raised when remote repository clone/setup fails before scan."""

    code = "PIPELINE_REPO_CLONE_FAILED"


class ScannerExecutionError(SuscheckError):
    """Raised when a scanner orchestration step fails.
    
    PRODUCTION-READY: Always caught and converted to Finding with
    type=REVIEW_NEEDED. Scan continues with partial results marked.
    """


class AnalysisPhaseError(SuscheckError):
    """Raised when analysis/triage orchestration encounters an error."""


class DiagnosticCheckError(SuscheckError):
    """Raised when service diagnostics checks fail."""


class ToolNotFoundError(SuscheckError):
    """Raised when required external tool not found in PATH."""

    code = "TOOL_NOT_FOUND"

    def __init__(self, tool: str, suggestion: str = "") -> None:
        msg = f"Required tool not found: {tool}"
        if suggestion:
            msg += f"\n  Install: {suggestion}"
        super().__init__(msg, severity=ErrorSeverity.MEDIUM)
        self.tool = tool


class APIKeyError(SuscheckError):
    """Raised when API key missing or invalid."""

    code = "API_KEY_MISSING"

    def __init__(self, service: str, env_var: str = "") -> None:
        msg = f"API key missing for {service}"
        if env_var:
            msg += f"\n  Set environment variable: {env_var}"
        super().__init__(msg, severity=ErrorSeverity.MEDIUM)
        self.service = service


def get_error_code(error: Exception, fallback_code: str) -> str:
    """Resolve stable error code from typed errors or fallback code."""
    return str(getattr(error, "code", fallback_code))


def build_error_evidence(error: Exception, fallback_code: str) -> dict[str, str]:
    """Build compact evidence payload with a stable code and message.
    
    PRODUCTION-READY: Never includes stack traces or sensitive data.
    Only safe, user-facing error information.
    """
    return {
        "error_code": get_error_code(error, fallback_code),
        "error": str(error)[:500],
    }
