"""Orchestrator for Checkov (Infrastructure as Code scanner)."""

import json
import logging
import subprocess
import shutil
from dataclasses import dataclass

from suscheck.core.finding import Finding, FindingType, Severity

logger = logging.getLogger(__name__)

@dataclass
class CheckovResult:
    """Result from a Checkov scan."""
    findings: list[Finding]
    errors: list[str]

class CheckovOrchestrator:
    """Wraps the Checkov CLI for IaC security scanning."""
    
    def __init__(self):
        # Checkov is installed via pip; it should be in the PATH of the venv
        self.cmd = shutil.which("checkov")
        self.is_installed = self.cmd is not None

    def _map_severity(self, checkov_severity: str | None) -> Severity:
        """Map Checkov severity to SusCheck severity."""
        if not checkov_severity:
            return Severity.MEDIUM
            
        mapping = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "INFO": Severity.INFO,
        }
        return mapping.get(checkov_severity.upper(), Severity.MEDIUM)

    def scan_file(self, file_path: str) -> CheckovResult:
        """Scan a configuration file with Checkov."""
        if not self.is_installed:
            return CheckovResult(findings=[], errors=["Checkov is not installed."])

        findings = []
        errors = []
        
        try:
            # Run checkov in JSON mode
            cmd = [
                self.cmd,
                "-f", file_path,
                "-o", "json",
                "--quiet",
                "--compact"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=45
            )
            
            # Checkov returns exit code 1 if findings are found, so we don't check returncode 0
            stdout = result.stdout.strip()
            if not stdout:
                # Might have printed to stderr if it didn't find any framework
                return CheckovResult(findings=[], errors=[])

            # Checkov might return a list of reports or a single report object
            try:
                data = json.loads(stdout)
            except json.JSONDecodeError:
                # Sometimes there's debug output before the JSON
                start = stdout.find("{")
                if start != -1:
                    try:
                        data = json.loads(stdout[start:])
                    except json.JSONDecodeError:
                        return CheckovResult(findings=[], errors=["Invalid JSON from Checkov"])
                else:
                    return CheckovResult(findings=[], errors=[])

            # Standardize to list of reports
            reports = data if isinstance(data, list) else [data]
                
            for report in reports:
                if not isinstance(report, dict):
                    continue
                    
                results = report.get("results", {})
                failed_checks = results.get("failed_checks", [])
                
                for check in failed_checks:
                    # Map Checkov finding to SusCheck Finding
                    check_id = check.get("check_id") or "UNKNOWN"
                    check_name = check.get("check_name") or "IaC Security Risk"
                    
                    # Preference for description: short_description -> description -> check_name
                    description = (
                        check.get("short_description") 
                        or check.get("description") 
                        or check_name
                    )
                    
                    severity_str = check.get("severity")
                    
                    # Extract line number
                    line_range = check.get("file_line_range", [0, 0])
                    line_number = line_range[0] if line_range else None
                    
                    findings.append(
                        Finding(
                            module="config_scanner_checkov",
                            finding_id=f"CKV-{check_id}",
                            title=check_name,
                            description=description,
                            severity=self._map_severity(severity_str),
                            finding_type=FindingType.CONFIG_RISK,
                            confidence=0.90,
                            file_path=file_path,
                            line_number=line_number,
                            mitre_ids=["T1082"], # General mapping
                            evidence={
                                "check_id": check_id,
                                "guideline": check.get("guideline", ""),
                                "actual_value": str(check.get("resource", ""))
                            }
                        )
                    )
        except Exception as e:
            errors.append(f"Checkov orchestration failed: {str(e)}")

        return CheckovResult(findings=findings, errors=errors)
