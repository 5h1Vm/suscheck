"""Code Scanner — Layer 1 orchestrator.

Runs all language-agnostic detectors on a file and returns
consolidated findings. This is the main entry point for
Tier 1 static analysis.
"""

import logging
import os
import time
from dataclasses import dataclass, field

from suscheck.core.finding import Finding

from .detectors.credentials import detect_credentials
from .detectors.dangerous_functions import detect_dangerous_functions
from .detectors.encoded_strings import detect_encoded_strings
from .detectors.entropy import detect_high_entropy
from .detectors.network_indicators import detect_network_indicators

logger = logging.getLogger(__name__)

# Maximum file size we'll analyze (5 MB)
MAX_FILE_SIZE = 5 * 1024 * 1024

# Binary file detection — if more than 10% of first 8KB is non-text
BINARY_CHECK_SIZE = 8192
BINARY_THRESHOLD = 0.10


@dataclass
class CodeScanResult:
    """Result of a Layer 1 code scan."""
    findings: list[Finding] = field(default_factory=list)
    scan_duration: float = 0.0
    detectors_ran: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    skipped_reason: str = ""


def _is_binary_file(file_path: str) -> bool:
    """Check if a file appears to be binary (not text).

    Reads the first 8KB and checks for non-text bytes.
    """
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(BINARY_CHECK_SIZE)
        if not chunk:
            return False

        # Count bytes that are clearly non-text
        # Text = printable ASCII (32-126), tabs, newlines, carriage returns
        non_text = sum(
            1 for b in chunk
            if b < 8 or (13 < b < 32) or b == 127
        )
        return (non_text / len(chunk)) > BINARY_THRESHOLD
    except OSError:
        return False


class CodeScanner:
    """Layer 1 — Language-agnostic code scanner.

    Runs all detectors on a file and returns consolidated findings.

    Usage:
        scanner = CodeScanner()
        result = scanner.scan_file("/path/to/file.py", language="python")
        for finding in result.findings:
            print(finding.title)
    """

    def __init__(self, max_file_size: int = MAX_FILE_SIZE):
        self.max_file_size = max_file_size

    def scan_file(
        self, file_path: str, language: str = "unknown"
    ) -> CodeScanResult:
        """Scan a file with all Layer 1 detectors.

        Args:
            file_path: Absolute path to the file.
            language: Detected language (e.g., "python", "javascript", "batch").

        Returns:
            CodeScanResult with all findings and metadata.
        """
        start_time = time.time()
        result = CodeScanResult()

        # ── Validate input ────────────────────────────────
        if not os.path.isfile(file_path):
            result.errors.append(f"File not found: {file_path}")
            result.skipped_reason = "file_not_found"
            return result

        file_size = os.path.getsize(file_path)
        if file_size > self.max_file_size:
            result.errors.append(
                f"File too large for code scan: {file_size:,} bytes "
                f"(max: {self.max_file_size:,})"
            )
            result.skipped_reason = "file_too_large"
            result.scan_duration = time.time() - start_time
            return result

        if file_size == 0:
            result.skipped_reason = "empty_file"
            result.scan_duration = time.time() - start_time
            return result

        # ── Check for binary files ────────────────────────
        if _is_binary_file(file_path):
            result.skipped_reason = "binary_file"
            result.scan_duration = time.time() - start_time
            logger.info(f"Skipped binary file: {file_path}")
            return result

        # ── Read file content ─────────────────────────────
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError as e:
            result.errors.append(f"Cannot read file: {e}")
            result.skipped_reason = "read_error"
            result.scan_duration = time.time() - start_time
            return result

        # ── Run all detectors ─────────────────────────────
        result = self.scan_content(content, file_path=file_path, language=language)
        result.scan_duration = time.time() - start_time
        return result

    def scan_content(
        self,
        content: str,
        file_path: str = "",
        language: str = "unknown",
    ) -> CodeScanResult:
        """Scan raw content with all Layer 1 detectors.

        Use this for scanning content that's not from a file (e.g.,
        downloaded package content, inline scripts).

        Args:
            content: Text content to scan.
            file_path: Optional path for finding metadata.
            language: Language hint.

        Returns:
            CodeScanResult with all findings.
        """
        result = CodeScanResult()

        # Run each detector and collect findings
        detectors = [
            ("encoded_strings", lambda: detect_encoded_strings(content, file_path)),
            ("network_indicators", lambda: detect_network_indicators(content, file_path)),
            ("entropy", lambda: detect_high_entropy(content, file_path)),
            ("credentials", lambda: detect_credentials(content, file_path)),
            ("dangerous_functions", lambda: detect_dangerous_functions(content, file_path, language)),
        ]

        for detector_name, detector_fn in detectors:
            try:
                detector_findings = detector_fn()
                result.findings.extend(detector_findings)
                result.detectors_ran.append(detector_name)
                logger.debug(
                    f"Detector {detector_name}: {len(detector_findings)} findings"
                )
            except Exception as e:
                error_msg = f"Detector {detector_name} failed: {e}"
                result.errors.append(error_msg)
                logger.error(error_msg, exc_info=True)

        # Deduplicate findings on the same line with the same module
        result.findings = self._deduplicate(result.findings)

        return result

    @staticmethod
    def _deduplicate(findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings (same line, same module, same title)."""
        seen: set[tuple] = set()
        unique: list[Finding] = []

        for f in findings:
            key = (f.module, f.line_number, f.title)
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique
