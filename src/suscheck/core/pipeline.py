"""Scanner pipeline orchestration for recursive directory scans and bulk analysis."""

import os
import time
from pathlib import Path
from typing import List, Set, Optional, TYPE_CHECKING
if TYPE_CHECKING:
    from suscheck.core.config_manager import ConfigManager

from suscheck.core.auto_detector import AutoDetector
from suscheck.core.finding import Finding, ScanSummary, Verdict
from suscheck.core.risk_aggregator import RiskAggregator
from suscheck.modules.code.scanner import CodeScanner
from suscheck.modules.config.scanner import ConfigScanner
from suscheck.modules.mcp.scanner import MCPScanner

class ScanPipeline:
    """Orchestrates complex scan workflows like recursive directory traversal."""

    def __init__(self, config: Optional["ConfigManager"] = None):
        self.config = config
        self.detector = AutoDetector()
        
        # Pull ignored directories from config or use defaults
        default_ignore = {
            ".git", ".github", "venv", ".venv", "__pycache__", 
            "node_modules", ".gemini", "dist", "build", ".pytest_cache"
        }
        if self.config:
            user_ignore = self.config.get("scanners.generic.ignore_dirs", [])
            self.ignore_dirs = set(default_ignore) | set(user_ignore)
        else:
            self.ignore_dirs = default_ignore

    def scan_directory(self, target_dir: str, skip_tier0: bool = True) -> List[Finding]:
        """Recursively scan a directory and return all findings."""
        all_findings: List[Finding] = []
        files_to_scan = []
        
        for root, dirs, files in os.walk(target_dir):
            # Prune ignore_dirs in-place
            dirs[:] = [d for d in dirs if d not in self.ignore_dirs]
            for f in files:
                files_to_scan.append(Path(root) / f)
        
        # In a real pipeline, we might use a thread pool here for performance,
        # but for v1 we stick to sequential robust scanning.
        for p in files_to_scan:
            try:
                findings = self.scan_single_file(p, skip_tier0=skip_tier0)
                all_findings.extend(findings)
            except Exception:
                continue
                
        return all_findings

    def scan_single_file(self, path: Path, skip_tier0: bool = True) -> List[Finding]:
        """Detect and scan a single file based on its type."""
        findings: List[Finding] = []
        det = self.detector.detect(str(path))
        
        # findings from auto-detector (mismatch, polyglot)
        if det.type_mismatch:
             # (Logic would go here, but usually we just want the scanner findings for bulk)
             pass

        if det.artifact_type.value == "code":
            scanner = CodeScanner()
            res = scanner.scan_file(str(path), language=det.language.value)
            findings.extend(res.findings)
        elif det.artifact_type.value == "config":
            scanner = ConfigScanner()
            res = scanner.scan(str(path))
            findings.extend(res.findings)
        elif det.artifact_type.value == "mcp_server":
            scanner = MCPScanner()
            res = scanner.scan(str(path))
            findings.extend(res.findings)
            
        return findings

    def get_modules_ran(self, findings: List[Finding]) -> Set[str]:
        """Identify which modules contributed findings."""
        return {f.module for f in findings}
