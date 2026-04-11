"""Orchestrator for Checkmarx KICS (Keeping Infrastructure as Code Secure)."""

import json
import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from suscheck.core.finding import Finding, FindingType, Severity

logger = logging.getLogger(__name__)


@dataclass
class KicsResult:
    """Result from a KICS scan."""
    findings: list[Finding]
    errors: list[str]


class KicsOrchestrator:
    """Wraps the Checkmarx KICS binary if available."""

    def __init__(self):
        self.kics_path = shutil.which("kics")
        self.is_installed = self.kics_path is not None

    def _map_severity(self, kics_severity: str) -> Severity:
        """Map KICS severity to SusCheck severity."""
        mapping = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
            "trace": Severity.INFO,
        }
        return mapping.get(kics_severity.lower(), Severity.INFO)

    def scan_file(self, file_path: str) -> KicsResult:
        """Scan a generic IaC configuration file with KICS."""
        if not self.is_installed:
            return KicsResult(findings=[], errors=["KICS is not installed. Skip mapping."])

        findings = []
        errors = []

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            report_path = temp_path / "kics_results.json"
            
            # KICS command structure
            cmd = [
                self.kics_path,
                "scan",
                "-p", str(file_path),
                "--output-path", str(temp_path),
                "--output-name", "kics_results",
                "--report-formats", "json",
                "--no-progress",
                "--ignore-on-exit", "all",  # Don't fail the command if vulnerabilites exist
            ]
            
            try:
                result = subprocess.run(
                    cmd, 
                    capture_output=True, 
                    text=True, 
                    timeout=30
                )
                
                if not report_path.exists():
                    # KICS might silently fail or not generate if 0 lines processed
                    logger.debug(f"KICS produced no report for {file_path}")
                    return KicsResult(findings=[], errors=errors)

                with open(report_path, "r") as f:
                    data = json.load(f)

                # Process results from `queries` array inside `data`
                queries = data.get("queries", [])
                for q in queries:
                    q_name = q.get("query_name", "KICS Vulnerability")
                    q_id = q.get("query_id", "KICS-UNKNOWN")
                    q_desc = q.get("description", "No description provided.")
                    severity = self._map_severity(q.get("severity", "INFO"))
                    
                    for f_detail in q.get("files", []):
                        findings.append(
                            Finding(
                                module="config_scanner_kics",
                                finding_id=f"KICS-{q_id}",
                                title=q_name,
                                description=f_detail.get("issue_type", q_desc),
                                severity=severity,
                                finding_type=FindingType.CONFIG_RISK,
                                confidence=0.85,
                                file_path=file_path,
                                line_number=f_detail.get("line", None),
                                mitre_ids=["T1082"],  # System Info Discovery (general mapping fallback)
                                evidence={
                                    "actual_value": f_detail.get("actual_value", ""),
                                    "expected_value": f_detail.get("expected_value", "")
                                }
                            )
                        )

            except subprocess.TimeoutExpired:
                errors.append("KICS scan timed out.")
            except Exception as e:
                errors.append(f"KICS orchestration failed: {str(e)}")

        return KicsResult(findings=findings, errors=errors)
