"""Runner for OpenVAS optional adapter (disabled by default)."""

from __future__ import annotations

import os
import shlex
import subprocess
from dataclasses import dataclass

from suscheck.core.finding import Finding, FindingType, Severity
from suscheck.core.tool_registry import ToolType, get_tool_registry


@dataclass
class OpenVASResult:
    findings: list[Finding]
    errors: list[str]


class OpenVASRunner:
    """Execute OpenVAS through a configurable command template.

    OpenVAS deployments vary (daemon/auth/socket/API wrappers), so runtime command
    is provided via environment variable `SUSCHECK_OPENVAS_SCAN_CMD` with `{target}`.
    Example:
      SUSCHECK_OPENVAS_SCAN_CMD="gvm-cli tls --hostname 127.0.0.1 --xml '<scan target=\"{target}\"/>'"
    """

    def __init__(self):
        status = get_tool_registry().register_tool(ToolType.OPENVAS)
        self.cmd = status.path
        self.is_installed = status.available
        self.missing_tool_message = status.suggestion or "Install from: https://greenbone.github.io/docs/latest/22.4/source-build/"

    def scan_target(self, target: str) -> OpenVASResult:
        if not self.is_installed:
            return OpenVASResult(
                findings=[],
                errors=[f"OpenVAS not installed. {self.missing_tool_message}"],
            )

        template = os.environ.get("SUSCHECK_OPENVAS_SCAN_CMD", "").strip()
        if not template:
            return OpenVASResult(
                findings=[],
                errors=[
                    "OpenVAS adapter enabled but SUSCHECK_OPENVAS_SCAN_CMD is not configured. "
                    "Set a command template containing {target}."
                ],
            )
        if "{target}" not in template:
            return OpenVASResult(
                findings=[],
                errors=["SUSCHECK_OPENVAS_SCAN_CMD must contain '{target}' placeholder."],
            )

        rendered = template.format(target=target)
        cmd = shlex.split(rendered)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        except subprocess.TimeoutExpired:
            return OpenVASResult(findings=[], errors=["OpenVAS scan timed out."])
        except Exception as exc:
            return OpenVASResult(findings=[], errors=[f"OpenVAS execution failed: {exc}"])

        findings: list[Finding] = []
        errors: list[str] = []
        combined = "\n".join([proc.stdout or "", proc.stderr or ""]).strip()

        # Output-agnostic parsing fallback for configurable integrations.
        for line in combined.splitlines():
            text = line.strip()
            if not text:
                continue
            upper = text.upper()
            if "CRITICAL" in upper or "SEVERITY: 10" in upper:
                findings.append(
                    Finding(
                        module="openvas",
                        finding_id="OPENVAS-CRITICAL",
                        title="OpenVAS reported critical infrastructure risk",
                        description=text,
                        severity=Severity.CRITICAL,
                        finding_type=FindingType.VULNERABILITY,
                        confidence=0.85,
                        file_path=target,
                        evidence={"source": "openvas-cmd", "line": text},
                    )
                )
            elif "HIGH" in upper or "SEVERITY: 7" in upper:
                findings.append(
                    Finding(
                        module="openvas",
                        finding_id="OPENVAS-HIGH",
                        title="OpenVAS reported high infrastructure risk",
                        description=text,
                        severity=Severity.HIGH,
                        finding_type=FindingType.VULNERABILITY,
                        confidence=0.8,
                        file_path=target,
                        evidence={"source": "openvas-cmd", "line": text},
                    )
                )

        if proc.returncode != 0 and not findings:
            snippet = combined[:500] if combined else "unknown error"
            errors.append(f"OpenVAS scan failed: {snippet}")

        return OpenVASResult(findings=findings, errors=errors)