"""Standardized Finding model used by all scanner modules."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingType(Enum):
    C2_COMMUNICATION = "c2_communication"
    C2_INDICATOR = "c2_indicator"
    ENCODED_PAYLOAD = "encoded_payload"
    SECRET_EXPOSURE = "secret_exposure"
    SECRET = "secret"
    REVERSE_SHELL = "reverse_shell"
    OBFUSCATION = "obfuscation"
    VULNERABILITY = "vulnerability"
    TYPOSQUATTING = "typosquatting"
    MAINTAINER_RISK = "maintainer_risk"
    TAKEOVER = "takeover"
    INSTALL_SCRIPT_RISK = "install_script_risk"
    DEPENDENCY_CONFUSION = "dependency_confusion"
    METADATA_MISMATCH = "metadata_mismatch"
    CVE = "cve"
    MCP_OVERPRIVILEGE = "mcp_overprivilege"
    PROMPT_INJECTION = "prompt_injection"
    CONFIG_RISK = "config_risk"
    DANGEROUS_FUNCTION = "dangerous_function"
    SUSPICIOUS_BEHAVIOR = "suspicious_behavior"
    NETWORK_INDICATOR = "network_indicator"
    EVASION = "evasion"
    DATA_EXFILTRATION = "data_exfiltration"
    PERSISTENCE = "persistence"
    DEFENSE_EVASION = "defense_evasion"
    POLYGLOT = "polyglot"
    FILE_MISMATCH = "file_mismatch"
    REVIEW_NEEDED = "review_needed"
    TRANSITIVE_DEPENDENCY = "transitive_dependency"
    ABANDONED_PACKAGE = "abandoned_package"
    MALICIOUS_RELEASE = "malicious_release"


class Verdict(Enum):
    CLEAR = "clear"
    CAUTION = "caution"
    HOLD = "hold"
    ABORT = "abort"


@dataclass
class Finding:
    """A single security finding from any scanner module."""

    module: str
    finding_id: str
    title: str
    description: str
    severity: Severity
    finding_type: FindingType
    confidence: float  # 0.0 to 1.0

    # Location
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None

    # Context
    context: str = "main"  # main, install_script, test, config, cicd

    # MITRE ATT&CK
    mitre_ids: list[str] = field(default_factory=list)

    # Evidence
    evidence: dict = field(default_factory=dict)

    # Human review flag
    needs_human_review: bool = False
    review_reason: Optional[str] = None

    # AI triage (filled later)
    ai_explanation: Optional[str] = None
    ai_false_positive: bool = False
    ai_confidence: Optional[float] = None


@dataclass
class ScanSummary:
    """Summary of a complete scan."""

    target: str
    artifact_type: str
    pri_score: int  # 0-100
    verdict: Verdict
    findings: list[Finding]
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    review_count: int
    scan_duration: float
    modules_ran: list[str]
    modules_skipped: list[str] = field(default_factory=list)
    vt_result: Optional[dict] = None
    trust_score: Optional[float] = None
