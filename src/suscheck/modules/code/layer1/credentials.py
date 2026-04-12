"""Credential Detector — finds hardcoded secrets, API keys, tokens, and passwords.

Pattern-based detection for known credential formats. Unlike Shannon
entropy (which is generic), this detector targets specific, well-known
credential patterns with high precision.
"""

import logging
import re
from dataclasses import dataclass

from suscheck.core.finding import Finding, FindingType, Severity

logger = logging.getLogger(__name__)


@dataclass
class CredentialPattern:
    """Definition of a credential pattern to detect."""
    pattern_id: str
    name: str
    regex: re.Pattern
    severity: Severity
    confidence: float
    description: str
    mitre_ids: list[str]


# ── Credential pattern definitions ─────────────────────────────────
# Each pattern has a regex, severity, and description.
# Patterns are ordered roughly by severity/commonality.

CREDENTIAL_PATTERNS: list[CredentialPattern] = [
    # AWS
    CredentialPattern(
        pattern_id="CRED-AWS-KEY",
        name="AWS Access Key ID",
        regex=re.compile(r'(AKIA[0-9A-Z]{16})', re.ASCII),
        severity=Severity.CRITICAL,
        confidence=0.95,
        description="AWS Access Key ID detected. This grants API access to AWS services.",
        mitre_ids=["T1552.001", "T1078.004"],
    ),
    CredentialPattern(
        pattern_id="CRED-AWS-SECRET",
        name="AWS Secret Access Key",
        regex=re.compile(
            r'(?:aws_secret_access_key|aws_secret|secret_key)\s*[=:]\s*["\']?'
            r'([A-Za-z0-9/+=]{40})["\']?',
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
        confidence=0.90,
        description="AWS Secret Access Key detected. Combined with Access Key ID, this grants full AWS API access.",
        mitre_ids=["T1552.001", "T1078.004"],
    ),

    # GitHub
    CredentialPattern(
        pattern_id="CRED-GITHUB-PAT",
        name="GitHub Personal Access Token",
        regex=re.compile(r'(gh[ps]_[A-Za-z0-9_]{36,})', re.ASCII),
        severity=Severity.CRITICAL,
        confidence=0.95,
        description="GitHub Personal Access Token detected. Grants API access to GitHub repositories.",
        mitre_ids=["T1552.001"],
    ),
    CredentialPattern(
        pattern_id="CRED-GITHUB-OAUTH",
        name="GitHub OAuth Token",
        regex=re.compile(r'(gho_[A-Za-z0-9_]{36,})', re.ASCII),
        severity=Severity.CRITICAL,
        confidence=0.95,
        description="GitHub OAuth Access Token detected.",
        mitre_ids=["T1552.001"],
    ),

    # Private Keys
    CredentialPattern(
        pattern_id="CRED-PRIVATE-KEY",
        name="Private Key",
        regex=re.compile(
            r'-----BEGIN\s+(?:RSA\s+|DSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----'
        ),
        severity=Severity.CRITICAL,
        confidence=0.98,
        description="Private key detected. This is a cryptographic secret that should never be in source code.",
        mitre_ids=["T1552.004"],  # Private Keys
    ),

    # Generic API Keys with common variable names
    CredentialPattern(
        pattern_id="CRED-API-KEY",
        name="Generic API Key",
        regex=re.compile(
            r'(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\s*[=:]\s*'
            r'["\']([a-zA-Z0-9_\-]{20,})["\']',
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        confidence=0.70,
        description="Hardcoded API key/secret detected.",
        mitre_ids=["T1552.001"],
    ),

    # Generic Passwords
    CredentialPattern(
        pattern_id="CRED-PASSWORD",
        name="Hardcoded Password",
        regex=re.compile(
            r'(?:password|passwd|pwd|pass)\s*[=:]\s*["\']([^"\']{4,})["\']',
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        confidence=0.60,
        description="Hardcoded password detected. Passwords should never be stored in source code.",
        mitre_ids=["T1552.001"],
    ),

    # Generic Secrets / Tokens
    CredentialPattern(
        pattern_id="CRED-SECRET",
        name="Hardcoded Secret",
        regex=re.compile(
            r'(?:secret|secret[_-]?key)\s*[=:]\s*["\']([a-zA-Z0-9_\-/+=]{8,100})["\']',
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        confidence=0.55,
        description="Hardcoded secret value detected.",
        mitre_ids=["T1552.001"],
    ),

    # Auth Tokens
    CredentialPattern(
        pattern_id="CRED-AUTH-TOKEN",
        name="Authentication Token",
        regex=re.compile(
            r'(?:auth[_-]?token|bearer[_-]?token|access[_-]?token)\s*[=:]\s*'
            r'["\']([a-zA-Z0-9_\-./+=]{20,200})["\']',
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        confidence=0.70,
        description="Hardcoded authentication token detected.",
        mitre_ids=["T1552.001"],
    ),

    # Slack
    CredentialPattern(
        pattern_id="CRED-SLACK",
        name="Slack Token",
        regex=re.compile(r'(xox[baprs]-[0-9a-zA-Z\-]{10,})', re.ASCII),
        severity=Severity.HIGH,
        confidence=0.90,
        description="Slack API token detected.",
        mitre_ids=["T1552.001"],
    ),

    # Stripe
    CredentialPattern(
        pattern_id="CRED-STRIPE",
        name="Stripe API Key",
        regex=re.compile(r'(sk_live_[0-9a-zA-Z]{24,})', re.ASCII),
        severity=Severity.CRITICAL,
        confidence=0.95,
        description="Stripe live secret key detected. This gives full access to payment processing.",
        mitre_ids=["T1552.001"],
    ),

    # Google
    CredentialPattern(
        pattern_id="CRED-GOOGLE",
        name="Google API Key",
        regex=re.compile(r'(AIza[0-9A-Za-z_\-]{35})', re.ASCII),
        severity=Severity.HIGH,
        confidence=0.85,
        description="Google API key detected.",
        mitre_ids=["T1552.001"],
    ),

    # Database connection strings
    CredentialPattern(
        pattern_id="CRED-DB-URI",
        name="Database Connection String",
        regex=re.compile(
            r'(?:mysql|postgres|postgresql|mongodb|redis|mssql)://[^\s"\']{10,}',
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        confidence=0.75,
        description="Database connection string with potential credentials detected.",
        mitre_ids=["T1552.001"],
    ),
]


def _is_placeholder(value: str) -> bool:
    """Check if a matched value is a placeholder, not a real credential."""
    lower = value.lower()
    placeholders = (
        "xxx", "your_", "your-", "replace", "changeme", "TODO",
        "example", "placeholder", "insert", "<", ">", "${",
        "none", "null", "empty", "test", "dummy", "fake",
        "sample", "demo", "CHANGEME", "REPLACE_ME",
        "os.environ", "os.getenv", "env(", "config(",
        "process.env",
    )
    if any(ph in lower for ph in placeholders):
        return True

    # Empty or whitespace-only
    if not value.strip() or value.strip() == '""' or value.strip() == "''":
        return True

    # All same character (e.g., "xxxxxxxxxxxx")
    if len(set(value)) <= 2:
        return True

    return False


def _is_in_comment(line: str) -> bool:
    """Check if the match is inside a comment."""
    stripped = line.lstrip()
    return (
        stripped.startswith("#")
        or stripped.startswith("//")
        or stripped.startswith("*")
        or stripped.startswith("/*")
        or stripped.startswith("REM ")
        or stripped.startswith("::")
    )


def detect_credentials(
    content: str, file_path: str = ""
) -> list[Finding]:
    """Scan file content for hardcoded credentials.

    Args:
        content: File content as string.
        file_path: Path to file (for finding metadata).

    Returns:
        List of Finding objects for detected credentials.
    """
    findings = []
    lines = content.split("\n")

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue

        for pattern in CREDENTIAL_PATTERNS:
            for m in pattern.regex.finditer(line):
                # Get the captured group (credential value) or full match
                value = m.group(1) if m.lastindex else m.group(0)

                # Skip placeholders
                if _is_placeholder(value):
                    continue

                # Lower confidence if in a comment
                confidence = pattern.confidence
                if _is_in_comment(line):
                    confidence *= 0.5
                    # Skip if confidence is now too low
                    if confidence < 0.25:
                        continue

                # Mask the credential for display
                if len(value) > 8:
                    masked = value[:4] + "*" * (len(value) - 8) + value[-4:]
                else:
                    masked = value[:2] + "***"

                findings.append(Finding(
                    module="code_scanner.credentials",
                    finding_id=f"{pattern.pattern_id}-{line_num:04d}",
                    title=f"{pattern.name}: {masked}",
                    description=pattern.description,
                    severity=pattern.severity,
                    finding_type=FindingType.SECRET,
                    confidence=confidence,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=stripped[:200],
                    mitre_ids=pattern.mitre_ids,
                    evidence={
                        "pattern": pattern.pattern_id,
                        "masked_value": masked,
                        "in_comment": _is_in_comment(line),
                    },
                ))

    return findings
