"""Tier 0 — Hash & Reputation engine.

Computes file hashes (SHA-256, MD5, SHA-1) and queries VirusTotal
for known malware reputation. This is the FIRST analysis step in
the pipeline and can short-circuit known-malicious files instantly.
"""

from suscheck.modules.external.hash_engine import HashEngine, HashResult
from suscheck.modules.external.virustotal import VirusTotalClient, VirusTotalResult
from suscheck.modules.external.engine import Tier0Engine, Tier0Result

__all__ = [
    "HashEngine",
    "HashResult",
    "VirusTotalClient",
    "VirusTotalResult",
    "Tier0Engine",
    "Tier0Result",
]
