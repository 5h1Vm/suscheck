"""Runner for OWASP Dependency-Check CLI."""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass
from pathlib import Path
import subprocess

from suscheck.core.finding import Finding, FindingType, Severity
from suscheck.core.tool_registry import ToolType, get_tool_registry


@dataclass
class DependencyCheckResult:
    findings: list[Finding]
    errors: list[str]


class DependencyCheckRunner:
    """Execute OWASP Dependency-Check and map results into SusCheck findings."""

    def __init__(self):
        status = get_tool_registry().register_tool(ToolType.DEPENDENCY_CHECK)
        self.cmd = status.path
        self.is_installed = status.available
        self.missing_tool_message = (
            status.suggestion
            or "Install from: https://owasp.org/www-project-dependency-check/"
        )

    @staticmethod
    def _map_severity(sev: str | None) -> Severity:
        value = (sev or "").strip().upper()
        if value == "CRITICAL":
            return Severity.CRITICAL
        if value == "HIGH":
            return Severity.HIGH
        if value == "MEDIUM":
            return Severity.MEDIUM
        if value == "LOW":
            return Severity.LOW
        return Severity.INFO

    def scan_directory(self, target_dir: str) -> DependencyCheckResult:
        if not self.is_installed:
            return DependencyCheckResult(
                findings=[],
                errors=[f"OWASP Dependency-Check not installed. {self.missing_tool_message}"],
            )

        findings: list[Finding] = []
        errors: list[str] = []

        with tempfile.TemporaryDirectory(prefix="suscheck-odc-") as tmpdir:
            out_dir = Path(tmpdir)
            cmd = [
                self.cmd,
                "--scan",
                str(target_dir),
                "--format",
                "JSON",
                "--out",
                str(out_dir),
                "--noupdate",
            ]

            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            except subprocess.TimeoutExpired:
                return DependencyCheckResult(findings=[], errors=["Dependency-Check scan timed out."])
            except Exception as exc:
                return DependencyCheckResult(findings=[], errors=[f"Dependency-Check execution failed: {exc}"])

            # Dependency-Check commonly returns non-zero when vulnerabilities are found.
            report_path = out_dir / "dependency-check-report.json"
            if not report_path.exists():
                stderr = (proc.stderr or "").strip()
                if stderr:
                    errors.append(f"Dependency-Check report missing. stderr: {stderr[:500]}")
                else:
                    errors.append("Dependency-Check report missing.")
                return DependencyCheckResult(findings=findings, errors=errors)

            try:
                report = json.loads(report_path.read_text(encoding="utf-8", errors="ignore"))
            except Exception as exc:
                return DependencyCheckResult(findings=[], errors=[f"Invalid Dependency-Check JSON report: {exc}"])

            for dep in report.get("dependencies", []) or []:
                dep_file = dep.get("filePath") or dep.get("fileName") or str(target_dir)
                for vuln in dep.get("vulnerabilities", []) or []:
                    vuln_name = vuln.get("name") or vuln.get("source") or "UNKNOWN"
                    sev = self._map_severity(vuln.get("severity"))
                    desc = vuln.get("description") or "Vulnerability reported by OWASP Dependency-Check"
                    cwes = vuln.get("cwes") or []
                    cvss = vuln.get("cvssv3") or vuln.get("cvssv2") or {}
                    score = cvss.get("baseScore") if isinstance(cvss, dict) else None

                    findings.append(
                        Finding(
                            module="dependency_check",
                            finding_id=f"ODC-{vuln_name}"[:72],
                            title=f"Dependency vulnerability: {vuln_name}",
                            description=desc,
                            severity=sev,
                            finding_type=FindingType.CVE,
                            confidence=0.95,
                            file_path=dep_file,
                            mitre_ids=["T1195"],
                            evidence={
                                "source": "owasp-dependency-check",
                                "vulnerability": vuln_name,
                                "severity": vuln.get("severity"),
                                "cwes": cwes,
                                "cvss_base_score": score,
                            },
                        )
                    )

        return DependencyCheckResult(findings=findings, errors=errors)
