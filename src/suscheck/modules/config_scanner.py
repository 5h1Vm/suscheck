"""Config and Infrastructure-as-Code Scanner Module.

Handles scanning Terraform, Kubernetes manifests, Dockerfiles, and CI/CD pipelines.
Orchestrates KICS and uses custom heuristics for malicious CI deployments.
"""

import re
import time
from pathlib import Path

from suscheck.core.finding import Finding, FindingType, Severity
from suscheck.modules.base import ModuleResult, ScannerModule
from suscheck.modules.config.kics_orchestrator import KicsOrchestrator


class ConfigScanner(ScannerModule):
    """Scanner for checking DevOps infrastructure payloads."""

    @property
    def name(self) -> str:
        return "config"

    def can_handle(self, artifact_type: str, file_path: str | None = None) -> bool:
        """Handle primarily config files or files named Dockerfile / .yaml."""
        if artifact_type.lower() == "config":
            return True
        if file_path:
            p = Path(file_path).name.lower()
            if "dockerfile" in p or p.endswith(".yml") or p.endswith(".yaml") or p.endswith(".json") or p == "jenkinsfile":
                return True
        return False

    def scan(self, target: str, config: dict | None = None) -> ModuleResult:
        """Execute the config scan."""
        start_time = time.time()
        findings = []
        errors = []

        try:
            target_path = Path(target)
            if not target_path.exists() or not target_path.is_file():
                return ModuleResult(
                    module_name=self.name,
                    findings=[],
                    scan_duration=time.time() - start_time,
                    error="Target is not a valid file."
                )

            # 1. Custom Rules for Configuration Overreach
            findings.extend(self._scan_custom_rules(target_path))

            # 2. Orchestrate KICS
            orchestrator = KicsOrchestrator()
            kics_res = orchestrator.scan_file(str(target_path))
            if kics_res.findings:
                findings.extend(kics_res.findings)
            if kics_res.errors:
                errors.extend(kics_res.errors)

        except Exception as e:
            errors.append(f"Config scanner failed completely: {str(e)}")

        return ModuleResult(
            module_name=self.name,
            findings=findings,
            scan_duration=time.time() - start_time,
            error="; ".join(errors) if errors else None
        )

    def _scan_custom_rules(self, file_path: Path) -> list[Finding]:
        """Apply fallback SusCheck-specific RegEx definitions."""
        findings = []
        try:
            content = file_path.read_text(errors="ignore")
        except Exception:
            return []

        # Rule 1: Malicious shell drops inside Docker/CI config
        curl_bash_pattern = re.compile(
            r'(curl|wget)[\s\w\-\:\/\.\?\&\=\%]+(\||\>)\s*(bash|sh|zsh)', 
            re.IGNORECASE
        )
        for i, line in enumerate(content.splitlines(), start=1):
            if match := curl_bash_pattern.search(line):
                findings.append(
                    Finding(
                        module="config_scanner_custom",
                        finding_id="SUS-CONF-CURL-BASH",
                        title="Remote code execution pipe via curl/wget into shell",
                        description="A payload is downloaded from the internet and piped directly into an execution shell. Highly abused in CI/CD pipeline attacks.",
                        severity=Severity.HIGH,
                        finding_type=FindingType.SUSPICIOUS_BEHAVIOR,
                        confidence=0.90,
                        file_path=str(file_path),
                        line_number=i,
                        code_snippet=line.strip(),
                        mitre_ids=["T1059.004"],
                        evidence={"matched": match.group(0)}
                    )
                )
                
        # Rule 2: Open root user in Docker
        if "dockerfile" in file_path.name.lower() and "USER root" in content:
           findings.append(
                Finding(
                    module="config_scanner_custom",
                    finding_id="SUS-CONF-DOCKER-ROOT",
                    title="Docker Root Privilege Execution",
                    description="The configuration executes as root inside the Docker image.",
                    severity=Severity.MEDIUM,
                    finding_type=FindingType.CONFIG_RISK,
                    confidence=1.0,
                    file_path=str(file_path),
                    mitre_ids=["T1611"],
                    evidence={"pattern": "USER root"}
                )
            )

        return findings
