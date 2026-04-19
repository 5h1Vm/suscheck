"""Tier 0 Engine — orchestrates hashing + VirusTotal lookup.

This is the first analysis step in the scan pipeline. It:
  1. Computes file hashes (SHA-256, MD5, SHA-1)
  2. Queries VirusTotal for known malware reputation
  3. Decides whether to SHORT-CIRCUIT (known malicious → ABORT)
     or continue to deeper analysis (Tier 1)
  4. Produces Finding objects for the PRI scoring pipeline

Short-circuit thresholds (from project spec):
  26+ VT detections  → ABORT immediately, skip further analysis
  4-25 detections     → CRITICAL finding, continue analysis
  1-3 detections      → MEDIUM finding, continue analysis
  0 detections        → positive signal (-5 PRI points)
  Not found           → neutral (0 PRI points), continue
  VT unavailable      → neutral (0 PRI points), continue
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from suscheck.core.finding import Finding, FindingType, Severity
from suscheck.modules.external.hash_engine import HashEngine, HashResult
from suscheck.modules.external.virustotal import VirusTotalClient, VirusTotalResult
from suscheck.services.fingerprint_service import FileFingerprint, Tier0FingerprintCache, build_file_fingerprint

logger = logging.getLogger(__name__)

# VT detection thresholds
VT_THRESHOLD_ABORT = 26
VT_THRESHOLD_HIGH = 4
VT_THRESHOLD_LOW = 1


@dataclass
class Tier0Result:
    """Result of Tier 0 analysis."""

    hash_result: Optional[HashResult] = None
    vt_result: Optional[VirusTotalResult] = None
    short_circuit: bool = False
    findings: list[Finding] = field(default_factory=list)
    pri_adjustment: int = 0  # Points to add/subtract from PRI
    scan_duration: float = 0.0
    errors: list[str] = field(default_factory=list)
    cache_hit: bool = False

    @property
    def vt_dict(self) -> Optional[dict]:
        """Return VT result as dict for terminal rendering."""
        if self.vt_result:
            return self.vt_result.to_dict()
        return None


class Tier0Engine:
    """Tier 0 — Hash & Reputation engine.

    Orchestrates hash computation and VirusTotal lookup.
    Produces findings and determines whether to short-circuit.

    Usage:
        engine = Tier0Engine()
        result = engine.check_file("/path/to/file.py")
        if result.short_circuit:
            # Known malicious — ABORT, skip further analysis
            ...
        else:
            # Continue to Tier 1 analysis
            ...
    """

    def __init__(
        self,
        vt_api_key: Optional[str] = None,
        max_file_size: int = 52_428_800,
    ):
        self.hasher = HashEngine(max_file_size=max_file_size)
        self.vt_client = VirusTotalClient(api_key=vt_api_key)
        self.fingerprint_cache = Tier0FingerprintCache()

    def check_file(self, file_path: str, upload_vt: bool = False) -> Tier0Result:
        """Run Tier 0 checks on a file.

        1. Compute hashes
        2. Query VirusTotal (if available)
        3. If hash not found and upload_vt=True, upload file for full AV scan
        4. Generate findings
        5. Determine short-circuit

        Args:
            file_path: Path to file to check.
            upload_vt: If True, upload file to VT when hash is unknown.
                       WARNING: uploaded files become PUBLICLY VISIBLE on VT.

        Returns:
            Tier0Result with hash data, VT results, findings, and
            short-circuit decision.
        """
        start_time = time.time()
        result = Tier0Result()

        # ── Step 1: Compute hashes ────────────────────────────────
        try:
            fingerprint = build_file_fingerprint(file_path)
            cached_hash = self.fingerprint_cache.get(fingerprint)
            if cached_hash:
                result.hash_result = cached_hash
                result.cache_hit = True
                logger.info(f"Tier 0 hash cache hit for {file_path}")
            else:
                result.hash_result = self.hasher.hash_file(file_path)
                self.fingerprint_cache.put(fingerprint, result.hash_result)
                logger.info(
                    f"Hashed {file_path}: SHA-256={result.hash_result.sha256[:16]}..."
                )
        except (FileNotFoundError, IsADirectoryError, ValueError, PermissionError) as e:
            result.errors.append(f"Hash computation failed: {e}")
            logger.error(f"Hash computation failed for {file_path}: {e}")
            result.scan_duration = time.time() - start_time
            return result

        # ── Step 2: VirusTotal lookup ─────────────────────────────
        if self.vt_client.available and result.hash_result:
            result.vt_result = self.vt_client.lookup_hash(
                result.hash_result.vt_lookup_hash
            )

            if result.vt_result and result.vt_result.found:
                self._process_vt_result(result)
            elif upload_vt:
                # Hash not found — upload file for full scan
                logger.info(
                    "Hash not in VT database. Uploading file for full scan "
                    "(--upload-vt enabled)..."
                )
                result.vt_result = self.vt_client.upload_file(file_path)
                if result.vt_result:
                    self._process_vt_result(result)
                else:
                    logger.info("VT upload returned no result")
                    self._add_not_found_finding(result)
            else:
                self._add_not_found_finding(result)
        else:
            if not self.vt_client.available:
                logger.info("VirusTotal lookup skipped: no API key configured")

        result.scan_duration = time.time() - start_time
        return result

    def check_bytes(self, data: bytes, label: str = "<bytes>") -> Tier0Result:
        """Run Tier 0 checks on raw bytes (e.g., downloaded package).

        Args:
            data: Raw bytes to check.
            label: Human-readable label for the data source.

        Returns:
            Tier0Result with hash data and VT results.
        """
        start_time = time.time()
        result = Tier0Result()

        result.hash_result = self.hasher.hash_bytes(data, label=label)

        if self.vt_client.available:
            result.vt_result = self.vt_client.lookup_hash(
                result.hash_result.vt_lookup_hash
            )
            if result.vt_result:
                self._process_vt_result(result)

        result.scan_duration = time.time() - start_time
        return result

    def _add_not_found_finding(self, result: Tier0Result) -> None:
        """Add a 'hash not found' informational finding."""
        result.findings.append(
            Finding(
                module="tier0",
                finding_id="VT-NOTFOUND-001",
                title="Hash not found in VirusTotal",
                description=(
                    "This file's hash is not in the VirusTotal database. "
                    "It may be a first-seen or uncommon artifact. "
                    "Use --upload-vt to upload the file for a full AV scan."
                ),
                severity=Severity.INFO,
                finding_type=FindingType.REVIEW_NEEDED,
                confidence=1.0,
                file_path=result.hash_result.file_path if result.hash_result else None,
                needs_human_review=True,
                review_reason="File hash not found in VirusTotal — first-seen artifact",
                evidence={
                    "sha256": result.hash_result.sha256 if result.hash_result else "",
                },
            )
        )

    def _process_vt_result(self, result: Tier0Result) -> None:
        """Process VT result: generate findings, set short-circuit, set PRI adjustment."""
        vt = result.vt_result
        if not vt:
            return

        if not vt.found:
            self._add_not_found_finding(result)
            return

        detections = vt.detection_count
        total = vt.total_engines

        if detections == 0:
            # Clean file — positive signal
            result.pri_adjustment = -5
            result.findings.append(
                Finding(
                    module="tier0",
                    finding_id="VT-CLEAN-001",
                    title="VirusTotal: Clean",
                    description=(
                        f"0/{total} security engines flagged this file. "
                        f"VirusTotal considers it clean."
                    ),
                    severity=Severity.INFO,
                    finding_type=FindingType.REVIEW_NEEDED,
                    confidence=1.0,
                    file_path=result.hash_result.file_path if result.hash_result else None,
                    evidence={
                        "vt_link": vt.vt_link,
                        "detection_count": 0,
                        "total_engines": total,
                    },
                )
            )

        elif detections < VT_THRESHOLD_LOW:
            # This shouldn't happen (1 <= detections < 1) but guard anyway
            pass

        elif detections < VT_THRESHOLD_HIGH:
            # 1-3 detections — low confidence, investigate
            result.pri_adjustment = 10
            threat_label = vt.suggested_threat_label or "unknown"
            result.findings.append(
                Finding(
                    module="tier0",
                    finding_id="VT-LOW-001",
                    title=f"VirusTotal: Low detections ({detections}/{total})",
                    description=(
                        f"{detections}/{total} security engines flagged this file. "
                        f"This is a low detection count and may be a false positive. "
                        f"Suggested threat: {threat_label}"
                    ),
                    severity=Severity.MEDIUM,
                    finding_type=FindingType.REVIEW_NEEDED,
                    confidence=0.5,
                    file_path=result.hash_result.file_path if result.hash_result else None,
                    needs_human_review=True,
                    review_reason=(
                        f"Low VT detection count ({detections}/{total}) — "
                        f"could be false positive or emerging threat"
                    ),
                    mitre_ids=["T1027"],  # Obfuscated Files or Information
                    evidence={
                        "vt_link": vt.vt_link,
                        "detection_count": detections,
                        "total_engines": total,
                        "detection_names": vt.detection_names[:5],
                        "threat_label": threat_label,
                    },
                )
            )

        elif detections < VT_THRESHOLD_ABORT:
            # 4-25 detections — moderate-high confidence malicious
            pri_add = 25 if detections <= 10 else 40
            result.pri_adjustment = pri_add
            threat_label = vt.suggested_threat_label or "unknown"

            severity = Severity.HIGH if detections <= 10 else Severity.CRITICAL
            confidence = min(0.7 + (detections / 100), 0.95)

            result.findings.append(
                Finding(
                    module="tier0",
                    finding_id="VT-MODERATE-001",
                    title=f"VirusTotal: {detections}/{total} engines detect this file",
                    description=(
                        f"{detections}/{total} security engines flagged this file as "
                        f"malicious or suspicious. Threat: {threat_label}. "
                        f"Further analysis recommended."
                    ),
                    severity=severity,
                    finding_type=FindingType.VULNERABILITY,
                    confidence=confidence,
                    file_path=result.hash_result.file_path if result.hash_result else None,
                    mitre_ids=["T1588.001"],  # Obtain Capabilities: Malware
                    evidence={
                        "vt_link": vt.vt_link,
                        "detection_count": detections,
                        "total_engines": total,
                        "detection_names": vt.detection_names[:10],
                        "threat_label": threat_label,
                        "tags": vt.tags,
                    },
                )
            )

        else:
            # 26+ detections — confirmed malicious, SHORT-CIRCUIT
            result.short_circuit = True
            result.pri_adjustment = 60
            threat_label = vt.suggested_threat_label or "confirmed malware"

            result.findings.append(
                Finding(
                    module="tier0",
                    finding_id="VT-MALICIOUS-001",
                    title=f"VirusTotal: CONFIRMED MALICIOUS ({detections}/{total})",
                    description=(
                        f"{detections}/{total} security engines detect this file as "
                        f"malicious. Threat classification: {threat_label}. "
                        f"SCAN SHORT-CIRCUITED — no further analysis needed."
                    ),
                    severity=Severity.CRITICAL,
                    finding_type=FindingType.VULNERABILITY,
                    confidence=0.99,
                    file_path=result.hash_result.file_path if result.hash_result else None,
                    mitre_ids=["T1588.001"],  # Obtain Capabilities: Malware
                    evidence={
                        "vt_link": vt.vt_link,
                        "detection_count": detections,
                        "total_engines": total,
                        "detection_names": vt.detection_names[:10],
                        "threat_label": threat_label,
                        "tags": vt.tags,
                        "short_circuit": True,
                    },
                )
            )
            logger.warning(
                f"SHORT-CIRCUIT: File is confirmed malicious "
                f"({detections}/{total} VT detections)"
            )
