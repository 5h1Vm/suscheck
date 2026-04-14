"""Network Indicator Detector — IPs, URLs, domains, C2 infrastructure.

Extracts network indicators from source code and classifies them:
- Known-bad destinations (paste sites, dynamic DNS, C2)
- Suspicious ports (reverse shell ports)
- Private IP ranges (legitimate vs suspicious context)
"""

import logging
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from suscheck.core.finding import Finding, FindingType, Severity

logger = logging.getLogger(__name__)

# ── Dynamic Config Loading ─────────────────────────────────────────

def _load_network_config() -> dict:
    project_root = Path(__file__).parent.parent.parent.parent.parent
    rules_path = project_root / "rules" / "network.toml"
    if not rules_path.exists():
        rules_path = Path("rules/network.toml")

    if rules_path.exists():
        try:
            with open(rules_path, "rb") as f:
                data = tomllib.load(f)
                return data.get("network", {})
        except Exception as e:
            logger.error(f"Failed to load network.toml: {e}")
    return {}

_NETWORK_CONFIG = _load_network_config()

# ── IPv4 regex ─────────────────────────────────────────────────────
# Matches 0-255.0-255.0-255.0-255 with word boundaries
IPV4_PATTERN = re.compile(
    r'\b((?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))\b'
)

# IPs to always ignore (not interesting)
IGNORED_IPS = set(_NETWORK_CONFIG.get("ignored_ips", [
    "0.0.0.0", "127.0.0.1", "255.255.255.255", "127.0.0.0", "0.0.0.1"
]))

# Private/link-local ranges that are usually benign
PRIVATE_PREFIXES = tuple(_NETWORK_CONFIG.get("private_prefixes", [
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", 
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", 
    "172.29.", "172.30.", "172.31.", "192.168.", "169.254."
]))

# ── URL regex ──────────────────────────────────────────────────────
URL_PATTERN = re.compile(
    r'(https?://[^\s"\'<>(){}\[\],;`]{1,500})',
    re.IGNORECASE,
)

# ── Domain regex (bare domains) ────────────────────────────────────
DOMAIN_PATTERN = re.compile(
    r'\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.'
    r'(?:com|net|org|io|xyz|tk|ml|ga|cf|gq|top|pw|cc|sh|me|info|'
    r'ru|cn|su|onion|bit))\b',
    re.IGNORECASE,
)

# ── Known-bad / suspicious destinations ────────────────────────────
PASTE_SITES = set(_NETWORK_CONFIG.get("paste_sites", []))
DYNAMIC_DNS = set(_NETWORK_CONFIG.get("dynamic_dns", []))
C2_INFRASTRUCTURE = set(_NETWORK_CONFIG.get("c2_infrastructure", []))

SUSPICIOUS_DOMAINS = PASTE_SITES | DYNAMIC_DNS

# ── Suspicious ports ───────────────────────────────────────────────
# Common reverse shell / C2 ports
SUSPICIOUS_PORTS = set(_NETWORK_CONFIG.get("suspicious_ports", [
    4444, 5555, 1337, 6666, 6667, 6668, 6669, 8888, 9999, 31337, 12345
]))

# Port extraction from URLs and connect() calls
PORT_PATTERN = re.compile(r':(\d{1,5})\b')


@dataclass
class NetworkMatch:
    """Detected network indicator."""
    indicator_type: str   # "ipv4", "url", "domain"
    value: str
    line_number: int
    category: str         # "paste_site", "dynamic_dns", "c2", "external_ip", "private_ip", "suspicious_port"
    full_line: str


def _categorize_ip(ip: str) -> Optional[str]:
    """Categorize an IP address. Returns None if should be ignored."""
    if ip in IGNORED_IPS:
        return None

    if any(ip.startswith(prefix) for prefix in PRIVATE_PREFIXES):
        return "private_ip"

    return "external_ip"


def _categorize_url(url: str) -> str:
    """Categorize a URL by its destination."""
    url_lower = url.lower()

    for domain in PASTE_SITES:
        if domain in url_lower:
            return "paste_site"

    for domain in DYNAMIC_DNS:
        if domain in url_lower:
            return "dynamic_dns"

    for pattern in C2_INFRASTRUCTURE:
        if pattern.startswith("*."):
            if url_lower.endswith(pattern[1:]):
                return "c2"
        elif pattern in url_lower:
            return "c2"

    # Check for suspicious ports in URL
    port_match = PORT_PATTERN.search(url)
    if port_match:
        port = int(port_match.group(1))
        if port in SUSPICIOUS_PORTS:
            return "suspicious_port"

    return "external_url"


def _categorize_domain(domain: str) -> str:
    """Categorize a bare domain."""
    domain_lower = domain.lower()

    if domain_lower in PASTE_SITES:
        return "paste_site"
    if domain_lower in DYNAMIC_DNS:
        return "dynamic_dns"
    if domain_lower.endswith(".onion"):
        return "c2"

    return "external_domain"


def _is_version_number(ip: str, line: str) -> bool:
    """Check if an IP-like pattern is actually a version number."""
    # version = "1.2.3.4", v1.2.3.4, Version: 1.2.3, etc.
    lower_line = line.lower()
    idx = lower_line.find(ip)
    if idx < 0:
        return False

    # Check context before the IP
    prefix = lower_line[max(0, idx - 30):idx]
    import re
    # Match whole words to avoid catching "server" because it ends with "ver"
    pattern = r'\b(?:version|ver|release|__version__|version_info)\b\s*[:=]?\s*["\']?\s*$'
    # Also match "v" prefix like v1.2.3
    pattern_v = r'\bv\s*["\']?\s*$'
    return bool(re.search(pattern, prefix) or re.search(pattern_v, prefix))



def detect_network_indicators(
    content: str, file_path: str = ""
) -> list[Finding]:
    """Scan file content for network indicators.

    Args:
        content: File content as string.
        file_path: Path to file (for finding metadata).

    Returns:
        List of Finding objects for detected network indicators.
    """
    findings = []
    lines = content.split("\n")
    matches: list[NetworkMatch] = []
    seen_values: set[str] = set()  # Dedup

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue

        # ── IPv4 addresses ────────────────────────────────
        for m in IPV4_PATTERN.finditer(line):
            ip = m.group(1)
            if ip in seen_values:
                continue

            # Skip version numbers
            if _is_version_number(ip, line):
                continue

            category = _categorize_ip(ip)
            if category:
                seen_values.add(ip)
                matches.append(NetworkMatch(
                    indicator_type="ipv4",
                    value=ip,
                    line_number=line_num,
                    category=category,
                    full_line=stripped[:200],
                ))

        # ── URLs ──────────────────────────────────────────
        for m in URL_PATTERN.finditer(line):
            url = m.group(1).rstrip(".,;:)")
            if url in seen_values:
                continue

            # Skip common safe URLs
            url_lower = url.lower()
            if any(safe in url_lower for safe in (
                "github.com", "stackoverflow.com", "docs.python.org",
                "pypi.org", "npmjs.com", "mozilla.org", "w3.org",
                "schemas.microsoft.com", "json-schema.org",
                "example.com", "example.org", "localhost",
            )):
                continue

            seen_values.add(url)
            category = _categorize_url(url)
            matches.append(NetworkMatch(
                indicator_type="url",
                value=url[:200],
                line_number=line_num,
                category=category,
                full_line=stripped[:200],
            ))

        # ── Bare domains ──────────────────────────────────
        for m in DOMAIN_PATTERN.finditer(line):
            domain = m.group(1)
            if domain in seen_values:
                continue
            # Skip if already captured as part of a URL
            if any(domain in v for v in seen_values if v.startswith("http")):
                continue
            # Skip very common domains
            if domain.lower() in ("google.com", "github.com", "python.org",
                                  "nodejs.org", "npmjs.com", "pypi.org"):
                continue

            category = _categorize_domain(domain)
            # Only report bare domains if they're suspicious
            if category in ("paste_site", "dynamic_dns", "c2"):
                seen_values.add(domain)
                matches.append(NetworkMatch(
                    indicator_type="domain",
                    value=domain,
                    line_number=line_num,
                    category=category,
                    full_line=stripped[:200],
                ))

    # ── Check for suspicious port usage ───────────────────
    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        lower = stripped.lower()
        # Look for connect/bind/listen with suspicious ports
        if any(kw in lower for kw in ("connect", "bind", "listen", "socket", "port")):
            for m in PORT_PATTERN.finditer(line):
                port_str = m.group(1)
                try:
                    port = int(port_str)
                except ValueError:
                    continue
                if port in SUSPICIOUS_PORTS:
                    key = f"port:{port}:{line_num}"
                    if key not in seen_values:
                        seen_values.add(key)
                        matches.append(NetworkMatch(
                            indicator_type="port",
                            value=str(port),
                            line_number=line_num,
                            category="suspicious_port",
                            full_line=stripped[:200],
                        ))

    # ── Convert to findings ───────────────────────────────
    CATEGORY_SEVERITY = {
        "paste_site": (Severity.HIGH, 0.80, "Data exfiltration to paste site"),
        "dynamic_dns": (Severity.HIGH, 0.80, "Dynamic DNS / tunneling service"),
        "c2": (Severity.CRITICAL, 0.90, "Potential C2 infrastructure"),
        "suspicious_port": (Severity.MEDIUM, 0.60, "Suspicious port (common C2/reverse shell)"),
        "external_ip": (Severity.LOW, 0.30, "Hardcoded external IP address"),
        "external_url": (Severity.LOW, 0.30, "External URL reference"),
        "external_domain": (Severity.LOW, 0.25, "External domain reference"),
        "private_ip": (Severity.INFO, 0.20, "Private IP address"),
    }

    for match in matches:
        severity, confidence, desc_prefix = CATEGORY_SEVERITY.get(
            match.category, (Severity.LOW, 0.3, "Network indicator")
        )

        # MITRE mappings
        mitre_map = {
            "paste_site": ["T1567.002"],    # Exfil via Web Service
            "dynamic_dns": ["T1572"],       # Protocol Tunneling
            "c2": ["T1071", "T1102"],       # Application Layer Protocol, Web Service
            "suspicious_port": ["T1571"],   # Non-Standard Port
            "external_ip": ["T1071"],       # App Layer Protocol
        }
        mitre_ids = mitre_map.get(match.category, [])

        finding_type = FindingType.NETWORK_INDICATOR
        if match.category in ("c2", "paste_site"):
            finding_type = FindingType.C2_INDICATOR

        findings.append(Finding(
            module="code_scanner.network",
            finding_id=f"NET-{match.indicator_type.upper()}-{match.line_number:04d}",
            title=f"{desc_prefix}: {match.value}",
            description=(
                f"Found {match.indicator_type} indicator on line {match.line_number}: "
                f"{match.value}. Category: {match.category}."
            ),
            severity=severity,
            finding_type=finding_type,
            confidence=confidence,
            file_path=file_path,
            line_number=match.line_number,
            code_snippet=match.full_line,
            mitre_ids=mitre_ids,
            evidence={
                "type": match.indicator_type,
                "value": match.value,
                "category": match.category,
            },
        ))

    return findings
