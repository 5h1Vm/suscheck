"""Repository Scanner Module.

Orchestrates Gitleaks for scanning entire directories or cloned repositories.
"""

import time
from pathlib import Path

from suscheck.modules.base import ModuleResult, ScannerModule
from suscheck.modules.repo.gitleaks_runner import GitleaksRunner


class RepoScanner(ScannerModule):
    """Scanner for analyzing directories and git histories."""

    @property
    def name(self) -> str:
        return "repo"

    def can_handle(self, artifact_type: str, file_path: str = "") -> bool:
        """Handle directories specifically."""
        if file_path:
            return Path(file_path).is_dir()
        return False

    def scan(self, target: str, config: dict | None = None) -> ModuleResult:
        """Execute the gitleaks scan against a target directory."""
        start_time = time.time()
        findings = []
        errors = []

        try:
            target_path = Path(target)
            if not target_path.exists() or not target_path.is_dir():
                return ModuleResult(
                    module_name=self.name,
                    findings=[],
                    scan_duration=time.time() - start_time,
                    error="Target is not a valid directory."
                )

            # Orchestrate Gitleaks
            runner = GitleaksRunner()
            gl_res = runner.scan_directory(str(target_path))
            
            if gl_res.findings:
                findings.extend(gl_res.findings)
            if gl_res.errors:
                errors.extend(gl_res.errors)

        except Exception as e:
            errors.append(f"Repo scanner failed completely: {str(e)}")

        return ModuleResult(
            module_name=self.name,
            findings=findings,
            scan_duration=time.time() - start_time,
            error="; ".join(errors) if errors else None
        )

    def scan_file_secrets(self, file_path: str) -> list:
        """Scan a single file specifically for secrets using Gitleaks."""
        # Note: Gitleaks detect --source <file> works for single files.
        # However, we need to handle non-git targets with --no-git.
        runner = GitleaksRunner()
        res = runner.scan_directory(file_path) # scan_directory handles files too
        return res.findings
