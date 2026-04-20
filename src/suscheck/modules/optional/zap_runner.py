"""Runner for ZAP optional adapter (disabled by default)."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

from suscheck.core.finding import Finding, FindingType, Severity
from suscheck.core.tool_registry import ToolType, get_tool_registry


@dataclass
class ZapResult:
    findings: list[Finding]
    errors: list[str]


class ZapRunner:
    """Execute OWASP ZAP quick scan and map notable output into SusCheck findings."""

    def __init__(self):
        status = get_tool_registry().register_tool(ToolType.ZAP)
        self.cmd = status.path
        self.is_installed = status.available
        self.missing_tool_message = status.suggestion or "Install from: https://www.zaproxy.org/download/"

    def scan_target(self, target: str) -> ZapResult:
        if not self.is_installed:
            return ZapResult(
                findings=[],
                errors=[f"ZAP not installed. {self.missing_tool_message}"],
            )

        cmd = [self.cmd, "-cmd", "-quickurl", target, "-quickprogress"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        except subprocess.TimeoutExpired:
            return ZapResult(findings=[], errors=["ZAP scan timed out."])
        except Exception as exc:
            return ZapResult(findings=[], errors=[f"ZAP execution failed: {exc}"])

        findings: list[Finding] = []
        errors: list[str] = []
        output_text = "\n".join([proc.stdout or "", proc.stderr or ""]).strip()

        # Keep parsing deterministic: classify alert lines from quick scan output.
        for line in output_text.splitlines():
            text = line.strip()
            if not text:
                continue
            upper = text.upper()
            if "FAIL-NEW" in upper or "FAIL-INPROG" in upper:
                findings.append(
                    Finding(
                        module="zap",
                        finding_id="ZAP-QUICK-HIGH-RISK",
                        title="ZAP quick scan reported high-risk web findings",
                        description=text,
                        severity=Severity.HIGH,
                        finding_type=FindingType.VULNERABILITY,
                        confidence=0.85,
                        file_path=target,
                        evidence={"source": "zaproxy-quick", "line": text},
                    )
                )
            elif "WARN-NEW" in upper or "WARN-INPROG" in upper:
                findings.append(
                    Finding(
                        module="zap",
                        finding_id="ZAP-QUICK-MEDIUM-RISK",
                        title="ZAP quick scan reported medium-risk web findings",
                        description=text,
                        severity=Severity.MEDIUM,
                        finding_type=FindingType.VULNERABILITY,
                        confidence=0.8,
                        file_path=target,
                        evidence={"source": "zaproxy-quick", "line": text},
                    )
                )

        if proc.returncode != 0 and not findings:
            snippet = output_text[:500] if output_text else "unknown error"
            errors.append(f"ZAP scan failed: {snippet}")

        return ZapResult(findings=findings, errors=errors)