"""Encoded String Detector — finds base64, hex, URL-encoded, Unicode-escaped,
XOR-obfuscated, and rot13-encoded strings.

Detects obfuscated payloads hidden in source code. For each match,
attempts to decode and checks if decoded content contains suspicious
patterns (URLs, IPs, shell commands).
"""

import base64
import binascii
import codecs
import logging
import re
import urllib.parse
from dataclasses import dataclass
from typing import Optional

from suscheck.core.finding import Finding, FindingType, Severity

logger = logging.getLogger(__name__)

# Minimum length for encoded strings to be worth checking
MIN_BASE64_LENGTH = 20
MIN_HEX_LENGTH = 16
MIN_URL_ENCODED_LENGTH = 10

# Regex patterns
# Base64: 20+ chars from base64 alphabet, optional padding
BASE64_PATTERN = re.compile(
    r'(?:(?:["\'])([A-Za-z0-9+/]{20,}={0,2})(?:["\']))'   # quoted
    r'|'
    r'(?:\b([A-Za-z0-9+/]{40,}={0,2})\b)',                # unquoted (longer threshold)
    re.ASCII,
)

# Hex strings: \x41\x42... or 0x41424344...
HEX_ESCAPE_PATTERN = re.compile(
    r'(?:\\x[0-9a-fA-F]{2}){4,}',       # \x41\x42\x43\x44...
)
HEX_LONG_PATTERN = re.compile(
    r'\b(?:0x)?([0-9a-fA-F]{16,})\b',   # 0x4142434445... or raw hex
)

# URL encoding: %41%42%43...
URL_ENCODED_PATTERN = re.compile(
    r'(?:%[0-9a-fA-F]{2}){5,}',         # 5+ consecutive %XX
)

# Unicode escapes: \u0041\u0042...
UNICODE_ESCAPE_PATTERN = re.compile(
    r'(?:\\u[0-9a-fA-F]{4}){3,}',       # 3+ consecutive \uXXXX
)

# Suspicious decoded content patterns
SUSPICIOUS_DECODED = re.compile(
    r'(?:http[s]?://|ftp://)'           # URLs
    r'|(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IPs
    r'|(?:powershell|cmd\.exe|/bin/(?:ba)?sh|bash\s+-[ci])'  # Shells
    r'|(?:eval|exec|system|popen|subprocess)'     # Dangerous funcs
    r'|(?:curl|wget|nc\s|ncat\s)'       # Network tools
    r'|(?:password|secret|token|api.key)',  # Secrets
    re.IGNORECASE,
)


@dataclass
class EncodedMatch:
    """A detected encoded string."""
    encoding_type: str       # "base64", "hex", "url_encoding", "unicode_escape"
    encoded_value: str       # The encoded string (truncated for display)
    decoded_value: str       # Decoded content
    line_number: int
    suspicious: bool         # Decoded content matches suspicious patterns
    full_line: str           # The line containing the match


def _is_printable_text(data: bytes) -> bool:
    """Check if decoded bytes look like readable text (not garbage)."""
    if not data:
        return False
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        try:
            text = data.decode("latin-1")
        except Exception:
            return False

    # At least 70% printable characters
    printable_count = sum(1 for c in text if c.isprintable() or c in '\n\r\t ')
    return (printable_count / max(len(text), 1)) > 0.7


def _try_decode_base64(value: str) -> Optional[str]:
    """Try to decode a base64 string. Returns decoded text or None."""
    try:
        # Add padding if needed
        padded = value + '=' * (4 - len(value) % 4) if len(value) % 4 else value
        decoded = base64.b64decode(padded, validate=True)
        if _is_printable_text(decoded):
            return decoded.decode("utf-8", errors="replace")
    except (binascii.Error, ValueError):
        pass
    return None


def _try_decode_hex_escape(value: str) -> Optional[str]:
    """Decode \\x41\\x42... hex escapes."""
    try:
        hex_bytes = bytes.fromhex(
            value.replace("\\x", "").replace("\\X", "")
        )
        if _is_printable_text(hex_bytes):
            return hex_bytes.decode("utf-8", errors="replace")
    except (ValueError, binascii.Error):
        pass
    return None


def _try_decode_hex_long(value: str) -> Optional[str]:
    """Decode long hex strings like 0x4142434445..."""
    try:
        clean = value.replace("0x", "").replace("0X", "")
        if len(clean) % 2 != 0:
            return None
        hex_bytes = bytes.fromhex(clean)
        if _is_printable_text(hex_bytes):
            return hex_bytes.decode("utf-8", errors="replace")
    except (ValueError, binascii.Error):
        pass
    return None


def _try_decode_url(value: str) -> Optional[str]:
    """Decode URL-encoded string."""
    try:
        decoded = urllib.parse.unquote(value)
        if decoded != value:  # Actually decoded something
            return decoded
    except Exception:
        pass
    return None


def _try_decode_unicode_escape(value: str) -> Optional[str]:
    """Decode Unicode escape sequences like \\u0041\\u0042."""
    try:
        decoded = value.encode("utf-8").decode("unicode_escape")
        if decoded != value:
            return decoded
    except (UnicodeDecodeError, ValueError):
        pass
    return None


def _try_decode_rot13(value: str) -> Optional[str]:
    """Try rot13 decode. Returns decoded text if it looks suspicious."""
    try:
        decoded = codecs.decode(value, "rot_13")
        if decoded != value and SUSPICIOUS_DECODED.search(decoded):
            return decoded
    except Exception:
        pass
    return None


def _try_xor_single_byte(data: bytes) -> Optional[tuple[str, int]]:
    """Try XOR decode with all single-byte keys (0x01-0xFF).

    Returns (decoded_text, key) if any key produces suspicious text.
    Only tests keys that yield printable, suspicious output.
    """
    for key in range(1, 256):
        try:
            decoded_bytes = bytes(b ^ key for b in data)
            if not _is_printable_text(decoded_bytes):
                continue
            decoded = decoded_bytes.decode("utf-8", errors="replace")
            if SUSPICIOUS_DECODED.search(decoded):
                return (decoded, key)
        except Exception:
            continue
    return None


# Pattern to detect XOR usage in code (someone doing XOR obfuscation)
XOR_PATTERN = re.compile(
    r'(?:\bxor\b|\^\s*0x[0-9a-fA-F]{1,2}\b|\bord\(.{0,20}\)\s*\^)',
    re.IGNORECASE,
)

# ROT13-specific patterns in code
ROT13_PATTERN = re.compile(
    r'(?:rot13|rot_13|codecs\.decode\(.{0,50}rot)',
    re.IGNORECASE,
)




def detect_encoded_strings(
    content: str, file_path: str = ""
) -> list[Finding]:
    """Scan file content for encoded strings.

    Args:
        content: File content as string.
        file_path: Path to file (for finding metadata).

    Returns:
        List of Finding objects for detected encoded strings.
    """
    findings = []
    lines = content.split("\n")
    matches: list[EncodedMatch] = []

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Skip empty lines and pure comment lines
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            # Still check for encoded strings IN comments — that's suspicious too
            if not stripped:
                continue

        # ── Base64 ────────────────────────────────────────────
        for m in BASE64_PATTERN.finditer(line):
            value = m.group(1) or m.group(2)
            if not value or len(value) < MIN_BASE64_LENGTH:
                continue

            # Skip common false positives
            if _is_common_base64_fp(value):
                continue

            decoded = _try_decode_base64(value)
            if decoded:
                matches.append(EncodedMatch(
                    encoding_type="base64",
                    encoded_value=value[:80],
                    decoded_value=decoded[:200],
                    line_number=line_num,
                    suspicious=bool(SUSPICIOUS_DECODED.search(decoded)),
                    full_line=stripped[:200],
                ))

        # ── Hex escapes (\x41\x42...) ────────────────────────
        for m in HEX_ESCAPE_PATTERN.finditer(line):
            value = m.group(0)
            decoded = _try_decode_hex_escape(value)
            if decoded:
                matches.append(EncodedMatch(
                    encoding_type="hex_escape",
                    encoded_value=value[:80],
                    decoded_value=decoded[:200],
                    line_number=line_num,
                    suspicious=bool(SUSPICIOUS_DECODED.search(decoded)),
                    full_line=stripped[:200],
                ))

        # ── Long hex strings ─────────────────────────────────
        for m in HEX_LONG_PATTERN.finditer(line):
            value = m.group(1) or m.group(0)
            if len(value) < MIN_HEX_LENGTH:
                continue
            # Skip SHA-256/MD5/SHA-1 hash values (common in legitimate code)
            if len(value) in (32, 40, 64, 128):
                # Could be a hash — skip unless in suspicious context
                lower_line = line.lower()
                if any(kw in lower_line for kw in ("hash", "sha", "md5", "checksum", "digest")):
                    continue
            decoded = _try_decode_hex_long(value)
            if decoded:
                matches.append(EncodedMatch(
                    encoding_type="hex_string",
                    encoded_value=value[:80],
                    decoded_value=decoded[:200],
                    line_number=line_num,
                    suspicious=bool(SUSPICIOUS_DECODED.search(decoded)),
                    full_line=stripped[:200],
                ))

        # ── URL encoding (%41%42...) ─────────────────────────
        for m in URL_ENCODED_PATTERN.finditer(line):
            value = m.group(0)
            decoded = _try_decode_url(value)
            if decoded and len(decoded) > 3:
                matches.append(EncodedMatch(
                    encoding_type="url_encoding",
                    encoded_value=value[:80],
                    decoded_value=decoded[:200],
                    line_number=line_num,
                    suspicious=bool(SUSPICIOUS_DECODED.search(decoded)),
                    full_line=stripped[:200],
                ))

        # ── Unicode escapes (\u0041\u0042...) ────────────────
        for m in UNICODE_ESCAPE_PATTERN.finditer(line):
            value = m.group(0)
            decoded = _try_decode_unicode_escape(value)
            if decoded:
                matches.append(EncodedMatch(
                    encoding_type="unicode_escape",
                    encoded_value=value[:80],
                    decoded_value=decoded[:200],
                    line_number=line_num,
                    suspicious=bool(SUSPICIOUS_DECODED.search(decoded)),
                    full_line=stripped[:200],
                ))

        # ── ROT13 detection ──────────────────────────────────
        # Check if the line references rot13 and contains quoted strings
        if ROT13_PATTERN.search(line):
            # Extract quoted strings on this line and try rot13
            for qm in re.finditer(r'["\']([A-Za-z]{10,})["\']', line):
                qval = qm.group(1)
                decoded = _try_decode_rot13(qval)
                if decoded:
                    matches.append(EncodedMatch(
                        encoding_type="rot13",
                        encoded_value=qval[:80],
                        decoded_value=decoded[:200],
                        line_number=line_num,
                        suspicious=True,
                        full_line=stripped[:200],
                    ))

        # ── XOR obfuscation detection ────────────────────────
        if XOR_PATTERN.search(line):
            # Flag XOR usage as a finding directly (decoding XOR
            # requires runtime context — the recursive decoder in
            # Increment 5 will handle full multi-layer XOR decode)
            matches.append(EncodedMatch(
                encoding_type="xor_obfuscation",
                encoded_value=stripped[:80],
                decoded_value="[XOR pattern detected — needs deeper analysis]",
                line_number=line_num,
                suspicious=True,
                full_line=stripped[:200],
            ))

    # Convert matches to findings
    for match in matches:
        if match.suspicious:
            severity = Severity.HIGH
            finding_type = FindingType.ENCODED_PAYLOAD
            confidence = 0.85
            title = f"Suspicious encoded {match.encoding_type} string"
            description = (
                f"Found a {match.encoding_type}-encoded string that decodes to "
                f"suspicious content. Decoded: {match.decoded_value[:100]}"
            )
            mitre = ["T1027", "T1140"]  # Obfuscated Files, Deobfuscate/Decode
        else:
            severity = Severity.LOW
            finding_type = FindingType.OBFUSCATION
            confidence = 0.4
            title = f"Encoded {match.encoding_type} string"
            description = (
                f"Found a {match.encoding_type}-encoded string. "
                f"Decoded: {match.decoded_value[:100]}"
            )
            mitre = ["T1027"]

        findings.append(Finding(
            module="code_scanner.encoded_strings",
            finding_id=f"ENC-{match.encoding_type.upper()}-{match.line_number:04d}",
            title=title,
            description=description,
            severity=severity,
            finding_type=finding_type,
            confidence=confidence,
            file_path=file_path,
            line_number=match.line_number,
            code_snippet=match.full_line,
            mitre_ids=mitre,
            evidence={
                "encoding": match.encoding_type,
                "encoded": match.encoded_value,
                "decoded": match.decoded_value[:200],
                "suspicious": match.suspicious,
            },
        ))

    return findings


def _is_common_base64_fp(value: str) -> bool:
    """Filter out common base64 false positives."""
    # Too short to be meaningful after decode
    if len(value) < MIN_BASE64_LENGTH:
        return True

    # Common patterns that look like base64 but aren't
    # Long sequences of the same character
    if len(set(value.replace("=", ""))) < 4:
        return True

    # Looks like a long variable/function name (camelCase/snake_case)
    if "_" in value or (value[0].islower() and any(c.isupper() for c in value[1:])):
        if len(value) < 40:
            return True

    return False
