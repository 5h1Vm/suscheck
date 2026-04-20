"""Runner for Grype optional adapter (disabled by default)."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass

from suscheck.core.finding import Finding, FindingType, Severity
from suscheck.core.tool_registry import ToolType, get_tool_registry


@dataclass
class GrypeResult:
    findings: list[Finding]
    errors: list[str]


class GrypeRunner:
    """Execute Grype scan and map JSON output into SusCheck findings."""

    def __init__(self):
        status = get_tool_registry().register_tool(ToolType.GRYPE)
        self.cmd = status.path
        self.is_installed = status.available
        self.missing_tool_message = status.suggestion or "Install from: https://github.com/anchore/grype#installation"

    @staticmethod
    def _map_severity(sev: str | None) -> Severity:
        value = (sev or "").strip().lower()
        if value == "critical":
            return Severity.CRITICAL
        if value == "high":
            return Severity.HIGH
        if value == "medium":
            return Severity.MEDIUM
        if value == "low":
            return Severity.LOW
        return Severity.INFO

    def scan_target(self, target: str) -> GrypeResult:
        if not self.is_installed:
            return GrypeResult(
                findings=[],
                errors=[f"Grype not installed. {self.missing_tool_message}"],
            )

        cmd = [self.cmd, target, "-o", "json", "--quiet"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        except subprocess.TimeoutExpired:
            return GrypeResult(findings=[], errors=["Grype scan timed out."])
        except Exception as exc:
            return GrypeResult(findings=[], errors=[f"Grype execution failed: {exc}"])

        findings: list[Finding] = []
        errors: list[str] = []
        payload_text = proc.stdout or ""
        if not payload_text.strip():
            if proc.returncode != 0:
                stderr = (proc.stderr or "").strip()
                errors.append(f"Grype scan failed: {stderr[:500] if stderr else 'unknown error'}")
            return GrypeResult(findings=findings, errors=errors)

        try:
            report = json.loads(payload_text)
        except json.JSONDecodeError as exc:
            return GrypeResult(findings=[], errors=[f"Invalid Grype JSON output: {exc}"])

        for match in report.get("matches", []) or []:
            vulnerability = match.get("vulnerability") or {}
            artifact = match.get("artifact") or {}
            vuln_id = vulnerability.get("id") or "UNKNOWN"
            pkg_name = artifact.get("name") or "package"
            findings.append(
                Finding(
                    module="grype",
                    finding_id=f"GRYPE-{vuln_id}"[:72],
                    title=f"Dependency vulnerability: {vuln_id}",
                    description=vulnerability.get("description") or "Vulnerability reported by Grype.",
                    severity=self._map_severity(vulnerability.get("severity")),
                    finding_type=FindingType.CVE,
                    confidence=0.95,
                    file_path=target,
                    evidence={
                        "vulnerability": vuln_id,
                        "package": pkg_name,
                        "installed_version": artifact.get("version"),
                        "fix_versions": vulnerability.get("fix", {}).get("versions", []),
                        "source": "grype",
                    },
                )
            )

        if proc.returncode != 0 and not findings:
            stderr = (proc.stderr or "").strip()
            errors.append(f"Grype scan failed: {stderr[:500] if stderr else 'unknown error'}")

        return GrypeResult(findings=findings, errors=errors)