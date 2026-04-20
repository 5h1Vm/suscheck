"""Runner for Trivy optional adapter (disabled by default)."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass

from suscheck.core.finding import Finding, FindingType, Severity
from suscheck.core.tool_registry import ToolType, get_tool_registry


@dataclass
class TrivyResult:
    findings: list[Finding]
    errors: list[str]


class TrivyRunner:
    """Execute Trivy filesystem scan and map JSON output into SusCheck findings."""

    def __init__(self):
        status = get_tool_registry().register_tool(ToolType.TRIVY)
        self.cmd = status.path
        self.is_installed = status.available
        self.missing_tool_message = status.suggestion or "Install from: https://aquasecurity.github.io/trivy/"

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

    def scan_target(self, target: str) -> TrivyResult:
        if not self.is_installed:
            return TrivyResult(
                findings=[],
                errors=[f"Trivy not installed. {self.missing_tool_message}"],
            )

        cmd = [self.cmd, "fs", "--format", "json", "--quiet", target]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        except subprocess.TimeoutExpired:
            return TrivyResult(findings=[], errors=["Trivy scan timed out."])
        except Exception as exc:
            return TrivyResult(findings=[], errors=[f"Trivy execution failed: {exc}"])

        findings: list[Finding] = []
        errors: list[str] = []
        payload_text = proc.stdout or ""
        if not payload_text.strip():
            if proc.returncode != 0:
                stderr = (proc.stderr or "").strip()
                errors.append(f"Trivy scan failed: {stderr[:500] if stderr else 'unknown error'}")
            return TrivyResult(findings=findings, errors=errors)

        try:
            report = json.loads(payload_text)
        except json.JSONDecodeError as exc:
            return TrivyResult(findings=[], errors=[f"Invalid Trivy JSON output: {exc}"])

        for result in report.get("Results", []) or []:
            target_name = result.get("Target") or target
            for vuln in result.get("Vulnerabilities", []) or []:
                vuln_id = vuln.get("VulnerabilityID") or "UNKNOWN"
                pkg_name = vuln.get("PkgName") or "package"
                title = vuln.get("Title") or f"Dependency vulnerability: {vuln_id}"
                findings.append(
                    Finding(
                        module="trivy",
                        finding_id=f"TRIVY-{vuln_id}"[:72],
                        title=title,
                        description=vuln.get("Description") or "Vulnerability reported by Trivy.",
                        severity=self._map_severity(vuln.get("Severity")),
                        finding_type=FindingType.CVE,
                        confidence=0.95,
                        file_path=target_name,
                        evidence={
                            "vulnerability": vuln_id,
                            "package": pkg_name,
                            "installed_version": vuln.get("InstalledVersion"),
                            "fixed_version": vuln.get("FixedVersion"),
                            "source": "trivy",
                        },
                    )
                )

        if proc.returncode != 0 and not findings:
            stderr = (proc.stderr or "").strip()
            errors.append(f"Trivy scan failed: {stderr[:500] if stderr else 'unknown error'}")

        return TrivyResult(findings=findings, errors=errors)