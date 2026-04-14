"""Bandit SAST Orchestration: Python Security Scanner.

Executes Bandit against target Python files and parses the results
into standardized SusCheck Findings.
"""

import json
import logging
import subprocess
from dataclasses import dataclass, field
from typing import Optional

from suscheck.core.finding import Finding, FindingType, Severity
from suscheck.core.tool_registry import ToolType, get_tool_registry

logger = logging.getLogger(__name__)


@dataclass
class BanditResult:
    """Result of a Bandit scan."""
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    skipped_reason: str = ""
    is_installed: bool = True


class BanditRunner:
    """Orchestrates Bandit CLI executions for Python SAST tier."""

    def __init__(self):
        status = get_tool_registry().register_tool(ToolType.BANDIT)
        self.bandit_path = status.path
        self.is_installed = status.available
        self.missing_tool_message = status.suggestion or "Install from: https://github.com/PyCQA/bandit#setup-and-installation"

    def scan_file(self, file_path: str) -> BanditResult:
        """Run Bandit against a single Python file.

        Args:
            file_path: Absolute path to the file.

        Returns:
            BanditResult with parsed findings.
        """
        result = BanditResult(is_installed=self.is_installed)

        if not self.is_installed:
            result.skipped_reason = "bandit_not_installed"
            result.errors.append(f"Bandit is not installed. {self.missing_tool_message}")
            logger.warning("Bandit is not installed. Python SAST skipped.")
            return result

        try:
            # -f json: JSON output
            # -q: Quiet mode
            # -ll: Only medium and high severity
            cmd = [
                self.bandit_path,
                "-f", "json",
                "-q",
                file_path
            ]
            
            # Bandit exits with 1 if findings, 0 if clean
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            if process.returncode not in (0, 1):
                # Bandit might return other codes for internal errors
                if not process.stdout:
                    result.errors.append(f"Bandit failed: {process.stderr}")
                    result.skipped_reason = "execution_error"
                    return result

            # Parse JSON output
            try:
                output = json.loads(process.stdout)
                results = output.get("results", [])
                
                for item in results:
                    finding = self._parse_finding(item)
                    if finding:
                        result.findings.append(finding)

            except json.JSONDecodeError:
                result.errors.append("Failed to parse Bandit JSON output.")
                result.skipped_reason = "json_parse_error"

        except subprocess.TimeoutExpired:
            result.errors.append("Bandit execution timed out (>30s).")
            result.skipped_reason = "timeout"
        except Exception as e:
            result.errors.append(f"Bandit execution failed: {e}")
            result.skipped_reason = "unknown_error"

        return result

    def _parse_finding(self, item: dict) -> Optional[Finding]:
        """Convert a Bandit result item to a standard Finding."""
        try:
            test_id = item.get("test_id", "unknown")
            test_name = item.get("test_name", "Python security issue")
            issue_text = item.get("issue_text", "")
            issue_severity = item.get("issue_severity", "LOW").upper()
            issue_confidence = item.get("issue_confidence", "LOW").upper()
            
            severity_map = {
                "HIGH": Severity.HIGH,
                "MEDIUM": Severity.MEDIUM,
                "LOW": Severity.LOW,
            }
            severity = severity_map.get(issue_severity, Severity.INFO)
            
            # Map confidence to float
            confidence_map = {"HIGH": 0.9, "MEDIUM": 0.7, "LOW": 0.4}
            confidence = confidence_map.get(issue_confidence, 0.5)

            return Finding(
                module="bandit",
                finding_id=f"PYTHON-{test_id.upper()}",
                title=f"Bandit: {test_name}",
                description=issue_text,
                severity=severity,
                finding_type=FindingType.VULNERABILITY,
                confidence=confidence,
                file_path=item.get("filename", ""),
                line_number=item.get("line_number"),
                code_snippet=item.get("code", "").strip(),
                mitre_ids=[f"CWE-{item.get('issue_cwe', {}).get('id', 'N/A')}"],
                evidence={
                    "test_id": test_id,
                    "more_info": item.get("more_info", ""),
                    "severity_raw": issue_severity
                }
            )

        except Exception as e:
            logger.warning(f"Error parsing Bandit item: {e}")
            return None
