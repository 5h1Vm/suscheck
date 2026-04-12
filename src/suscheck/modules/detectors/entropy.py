"""Shannon Entropy Detector — finds high-entropy strings (potential secrets/keys).

Uses Shannon entropy to detect strings that look like:
- API keys
- Encrypted data / passwords
- Cryptographic material
- Obfuscated payloads

Excludes known patterns: import paths, UUIDs, hashes in comments, file paths.
"""

import logging
import math
import re
from collections import Counter
from dataclasses import dataclass

from suscheck.core.finding import Finding, FindingType, Severity

logger = logging.getLogger(__name__)

# Minimum length of a token to check entropy
MIN_TOKEN_LENGTH = 20
MAX_TOKEN_LENGTH = 500

# Shannon entropy thresholds
# English text is ~3.5-4.0 bits/char
# Random base64 is ~5.5-6.0 bits/char
# Random hex is ~3.5-4.0 bits/char (only 16 chars)
# API keys are typically 5.0-6.0 bits/char
ENTROPY_THRESHOLD_HIGH = 5.8   # High confidence secret/key
ENTROPY_THRESHOLD_MEDIUM = 5.2  # Likely suspicious

# Patterns to extract quotable strings (stuff in quotes or assignments)
STRING_PATTERN = re.compile(
    r'["\']([^"\']{20,})["\']'   # Content inside quotes
)

# Token pattern — word-like sequences
TOKEN_PATTERN = re.compile(
    r'[A-Za-z0-9+/=_\-]{20,}'
)

# Known false positive patterns
UUID_PATTERN = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE,
)

HASH_CONTEXT_KEYWORDS = (
    "hash", "sha256", "sha1", "md5", "checksum", "digest",
    "sha_256", "sha_1", "sha384", "sha512", "fingerprint",
)

# Import/path patterns
PATH_PATTERN = re.compile(
    r'^(?:/|\\|[a-zA-Z]:\\|\.\.?/)'  # Starts with path separator
    r'|(?:\.[a-zA-Z]{2,4}$)',        # Ends with file extension
)

IMPORT_KEYWORDS = ("import", "from", "require", "include", "using")


@dataclass
class EntropyMatch:
    """A string with high Shannon entropy."""
    value: str
    entropy: float
    line_number: int
    full_line: str
    in_string: bool  # Found inside quotes


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string.

    Returns:
        Bits per character. Higher = more random.
        - English text: ~3.5-4.0
        - Base64 encoded: ~5.5-6.0
        - API keys: ~5.0-6.0
        - Hex strings: ~3.5-4.0
    """
    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)
    entropy = 0.0

    for count in counts.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def _is_false_positive(value: str, line: str) -> bool:
    """Check if a high-entropy string is a common false positive."""
    # UUID
    if UUID_PATTERN.match(value):
        return True

    # File path
    if PATH_PATTERN.match(value):
        return True

    # In a hash context
    lower_line = line.lower()
    if any(kw in lower_line for kw in HASH_CONTEXT_KEYWORDS):
        return True

    # Import / require statement
    if any(lower_line.strip().startswith(kw) for kw in IMPORT_KEYWORDS):
        return True

    # All same character repeated
    if len(set(value)) < 4:
        return True

    # Looks like a URL (already caught by network detector)
    if value.startswith("http://") or value.startswith("https://"):
        return True

    # Base64-padded content that's very long (likely data, not secret)
    if len(value) > 200:
        return True

    return False


def detect_high_entropy(
    content: str, file_path: str = ""
) -> list[Finding]:
    """Scan file content for high-entropy strings.

    Args:
        content: File content as string.
        file_path: Path to file (for finding metadata).

    Returns:
        List of Finding objects for high-entropy strings.
    """
    findings = []
    lines = content.split("\n")
    seen_values: set[str] = set()

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue

        # Check quoted strings first (higher confidence)
        for m in STRING_PATTERN.finditer(line):
            value = m.group(1)
            if len(value) < MIN_TOKEN_LENGTH or len(value) > MAX_TOKEN_LENGTH:
                continue
            if value in seen_values:
                continue

            entropy = shannon_entropy(value)

            if entropy >= ENTROPY_THRESHOLD_MEDIUM:
                if _is_false_positive(value, line):
                    continue
                seen_values.add(value)

                if entropy >= ENTROPY_THRESHOLD_HIGH:
                    severity = Severity.MEDIUM
                    confidence = 0.65
                    title = f"High-entropy string (entropy={entropy:.1f})"
                else:
                    severity = Severity.LOW
                    confidence = 0.40
                    title = f"Elevated-entropy string (entropy={entropy:.1f})"

                findings.append(Finding(
                    module="code_scanner.entropy",
                    finding_id=f"ENTROPY-{line_num:04d}",
                    title=title,
                    description=(
                        f"Found a string with Shannon entropy {entropy:.2f} bits/char "
                        f"(threshold: {ENTROPY_THRESHOLD_MEDIUM}). "
                        f"Value: {value[:40]}... "
                        f"This may be an embedded secret, API key, or encrypted data."
                    ),
                    severity=severity,
                    finding_type=FindingType.SECRET,
                    confidence=confidence,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=stripped[:200],
                    mitre_ids=["T1552.001"],  # Unsecured Credentials: Credentials In Files
                    evidence={
                        "value_preview": value[:60],
                        "entropy": round(entropy, 2),
                        "length": len(value),
                        "in_quotes": True,
                    },
                ))

        # Check unquoted tokens (lower confidence — many FPs)
        for m in TOKEN_PATTERN.finditer(line):
            value = m.group(0)
            if len(value) < MIN_TOKEN_LENGTH or len(value) > MAX_TOKEN_LENGTH:
                continue
            if value in seen_values:
                continue

            entropy = shannon_entropy(value)

            # Higher threshold for unquoted tokens (more FPs)
            if entropy >= ENTROPY_THRESHOLD_HIGH:
                if _is_false_positive(value, line):
                    continue
                # Also skip if it looks like a function or variable name
                if "(" in line[line.find(value):line.find(value)+len(value)+2]:
                    continue
                seen_values.add(value)

                findings.append(Finding(
                    module="code_scanner.entropy",
                    finding_id=f"ENTROPY-{line_num:04d}",
                    title=f"High-entropy token (entropy={entropy:.1f})",
                    description=(
                        f"Found a token with Shannon entropy {entropy:.2f} bits/char. "
                        f"Value: {value[:40]}... "
                        f"This may be an embedded secret or obfuscated content."
                    ),
                    severity=Severity.LOW,
                    finding_type=FindingType.SECRET,
                    confidence=0.30,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=stripped[:200],
                    mitre_ids=["T1552.001"],
                    evidence={
                        "value_preview": value[:60],
                        "entropy": round(entropy, 2),
                        "length": len(value),
                        "in_quotes": False,
                    },
                ))

    return findings
