"""Runner for Nuclei optional adapter (disabled by default)."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass

from suscheck.core.finding import Finding, FindingType, Severity
from suscheck.core.tool_registry import ToolType, get_tool_registry


@dataclass
class NucleiResult:
    findings: list[Finding]
    errors: list[str]


class NucleiRunner:
    """Execute Nuclei and map JSONL output into SusCheck findings."""

    def __init__(self):
        status = get_tool_registry().register_tool(ToolType.NUCLEI)
        self.cmd = status.path
        self.is_installed = status.available
        self.missing_tool_message = status.suggestion or "Install from: https://docs.projectdiscovery.io/tools/nuclei/installation"

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

    def scan_target(self, target: str) -> NucleiResult:
        if not self.is_installed:
            return NucleiResult(
                findings=[],
                errors=[f"Nuclei not installed. {self.missing_tool_message}"],
            )

        cmd = [self.cmd, "-u", target, "-json", "-silent"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            return NucleiResult(findings=[], errors=["Nuclei scan timed out."])
        except Exception as exc:
            return NucleiResult(findings=[], errors=[f"Nuclei execution failed: {exc}"])

        findings: list[Finding] = []
        errors: list[str] = []

        stdout_text = proc.stdout or ""
        for line in stdout_text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                result = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = result.get("info") or {}
            template_id = result.get("template-id") or result.get("template") or "UNKNOWN"
            title = info.get("name") or f"Nuclei detection: {template_id}"

            findings.append(
                Finding(
                    module="nuclei",
                    finding_id=f"NUCLEI-{template_id}"[:72],
                    title=title,
                    description=info.get("description") or "Nuclei template matched target content.",
                    severity=self._map_severity(info.get("severity")),
                    finding_type=FindingType.VULNERABILITY,
                    confidence=0.9,
                    file_path=result.get("host") or target,
                    evidence={
                        "template_id": template_id,
                        "matched_at": result.get("matched-at"),
                        "matcher_name": result.get("matcher-name"),
                        "severity": info.get("severity"),
                    },
                )
            )

        if proc.returncode != 0 and not findings:
            stderr = (proc.stderr or "").strip()
            if stderr:
                errors.append(f"Nuclei scan failed: {stderr[:500]}")
            else:
                errors.append("Nuclei scan failed.")

        return NucleiResult(findings=findings, errors=errors)