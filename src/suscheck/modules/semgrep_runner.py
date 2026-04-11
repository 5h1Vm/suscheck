"""Layer 2 SAST Orchestration: Semgrep Runner.

Executes Semgrep against target files and parses the JSON results
into standardized SusCheck Findings.
"""

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Optional

from suscheck.core.finding import Finding, FindingType, Severity

logger = logging.getLogger(__name__)


@dataclass
class SemgrepResult:
    """Result of a Semgrep scan."""
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    skipped_reason: str = ""
    is_installed: bool = True
    semgrep_version: str = ""


class SemgrepRunner:
    """Orchestrates Semgrep CLI executions for Layer 2 analysis."""

    def __init__(self):
        self.semgrep_path = shutil.which("semgrep")
        self.is_installed = bool(self.semgrep_path)

    def scan_file(self, file_path: str, config: str = "auto") -> SemgrepResult:
        """Run Semgrep against a single file.

        Args:
            file_path: Absolute path to the file.
            config: Semgrep config string (default uses auto-detected rules).

        Returns:
            SemgrepResult with parsed findings.
        """
        result = SemgrepResult(is_installed=self.is_installed)

        if not self.is_installed:
            result.skipped_reason = "semgrep_not_installed"
            logger.info("Semgrep is not installed. Layer 2 SAST skipped.")
            return result

        try:
            cmd = [
                self.semgrep_path,
                "scan",
                "--json",
                "--quiet",
                "--config", config,
                file_path
            ]
            
            logger.debug(f"Running semgrep: {' '.join(cmd)}")
            
            # Semgrep exits with 1 if findings, 0 if clean, 2+ on error
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            if process.returncode >= 2:
                result.errors.append(f"Semgrep failed internally: {process.stderr}")
                result.skipped_reason = "execution_error"
                return result

            # Parse JSON output
            try:
                output = json.loads(process.stdout)
                semgrep_findings = output.get("results", [])
                
                # Extract version
                if "version" in output:
                     result.semgrep_version = output["version"]
                     
                for item in semgrep_findings:
                    finding = self._parse_finding(item, file_path)
                    if finding:
                        result.findings.append(finding)

            except json.JSONDecodeError:
                result.errors.append("Failed to parse Semgrep JSON output.")
                result.skipped_reason = "json_parse_error"

        except subprocess.TimeoutExpired:
            result.errors.append("Semgrep execution timed out (>60s).")
            result.skipped_reason = "timeout"
        except Exception as e:
            result.errors.append(f"Semgrep execution failed: {e}")
            result.skipped_reason = "unknown_error"

        return result

    def _parse_finding(self, item: dict, file_path: str) -> Optional[Finding]:
        """Convert a Semgrep JSON result to a standard Finding."""
        try:
            check_id = item.get("check_id", "unknown_rule")
            extra = item.get("extra", {})
            metadata = extra.get("metadata", {})
            
            # Parse severity
            sg_severity = extra.get("severity", "INFO").upper()
            severity_map = {
                "ERROR": Severity.HIGH,  # Semgrep ERROR usually means highly likely bug/vuln
                "WARNING": Severity.MEDIUM,
                "INFO": Severity.LOW,
            }
            severity = severity_map.get(sg_severity, Severity.INFO)
            
            # Extract line numbers
            start = item.get("start", {})
            line_number = start.get("line")
            
            # Extract message
            message = extra.get("message", "Semgrep security finding.")
            
            # Extract line snippet
            lines = extra.get("lines", "").strip()

            return Finding(
                module="semgrep",
                finding_id=f"SAST-{check_id.split('.')[-1][:15]}",
                title=f"SAST Finding: {check_id.split('.')[-1]}",
                description=message,
                severity=severity,
                finding_type=FindingType.VULNERABILITY,
                confidence=0.85, # Community rules are generally reliable
                file_path=file_path,
                line_number=line_number,
                code_snippet=lines[:200] if lines else None,
                mitre_ids=metadata.get("cwe", []),
                evidence={
                    "rule_id": check_id,
                    "cwe": metadata.get("cwe", []),
                    "owasp": metadata.get("owasp", []),
                    "severity": sg_severity
                }
            )

        except Exception as e:
            logger.warning(f"Error parsing Semgrep item: {e}")
            return None
