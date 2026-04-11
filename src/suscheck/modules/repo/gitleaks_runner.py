"""Gitleaks Orchestrator for detecting committed secrets."""

import json
import logging
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from suscheck.core.finding import Finding, FindingType, Severity

logger = logging.getLogger(__name__)


@dataclass
class GitleaksResult:
    """Findings extracted from Gitleaks."""
    findings: list[Finding]
    errors: list[str]


class GitleaksRunner:
    """Wraps the Gitleaks binary if available."""

    def __init__(self):
        self.gitleaks_path = shutil.which("gitleaks")
        self.is_installed = self.gitleaks_path is not None

    def scan_directory(self, target_dir: str) -> GitleaksResult:
        """Scan a repository or directory using Gitleaks."""
        if not self.is_installed:
            return GitleaksResult(
                findings=[], 
                errors=["Gitleaks is not installed on the system. Secret scanning skipped."]
            )

        findings = []
        errors = []
        
        target_path = Path(target_dir)

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            report_path = temp_path / "gitleaks_report.json"
            
            # Check if directory is actually a Git repo
            is_git = (target_path / ".git").exists()
            
            cmd = [
                self.gitleaks_path,
                "detect",
                "--source", str(target_path),
                "--report-path", str(report_path),
                "--report-format", "json",
                "--redact"  # Don't leak the full secret perfectly into our output trace
            ]
            
            if not is_git:
                cmd.append("--no-git")

            try:
                # Gitleaks returns exit code 1 if it finds secrets, 0 if clean.
                result = subprocess.run(
                    cmd, 
                    capture_output=True, 
                    text=True, 
                    timeout=60
                )
                
                # Check for critical crash vs "found vulnerabilities"
                if result.returncode not in (0, 1) and not report_path.exists():
                    errors.append(f"Gitleaks crashed: {result.stderr}")
                    return GitleaksResult(findings=findings, errors=errors)

                if report_path.exists():
                    with open(report_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    
                    for leak in data:
                        description = leak.get("Description", "Exposed Secret Detected")
                        file_match = leak.get("File", "Unknown")
                        commit = leak.get("Commit", "Uncommitted")
                        rule_id = leak.get("RuleID", "generic-secret")
                        secret_redacted = leak.get("Secret", "REDACTED")
                        
                        finding_desc = f"{description}"
                        if commit and commit != "Uncommitted":
                            finding_desc += f" (Found in commit {commit[:8]})"
                        
                        findings.append(
                            Finding(
                                module="gitleaks",
                                finding_id=f"LEAK-{rule_id.upper()}",
                                title=description,
                                description=finding_desc,
                                severity=Severity.CRITICAL,  # Secrets are always critical
                                finding_type=FindingType.SECRET_EXPOSURE,
                                confidence=1.0,
                                file_path=file_match,
                                line_number=leak.get("StartLine", None),
                                mitre_ids=["T1552.001", "T1552.005"],
                                evidence={
                                    "redacted_secret": secret_redacted,
                                    "commit": commit,
                                    "author": leak.get("Author", "")
                                }
                            )
                        )

            except subprocess.TimeoutExpired:
                errors.append("Gitleaks scan timed out.")
            except Exception as e:
                errors.append(f"Gitleaks orchestration failed: {str(e)}")

        return GitleaksResult(findings=findings, errors=errors)
