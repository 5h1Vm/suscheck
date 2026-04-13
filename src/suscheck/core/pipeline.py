"""Scanner pipeline orchestration for recursive directory scans and bulk analysis.

This is the 'Unified Forensic Brain' that coordinates industry-standard engines 
(Semgrep, Gitleaks, Checkov) into a single PRI verdict (Increment 18).
"""

import os
import time
from pathlib import Path
from typing import List, Set, Optional, TYPE_CHECKING, Dict, Any

if TYPE_CHECKING:
    from suscheck.core.config_manager import ConfigManager

from suscheck.core.auto_detector import AutoDetector, ArtifactType, Language
from suscheck.core.finding import Finding, ScanSummary, Verdict, Severity, FindingType
from suscheck.core.risk_aggregator import RiskAggregator
from suscheck.modules.code.scanner import CodeScanner
from suscheck.modules.config.scanner import ConfigScanner
from suscheck.modules.mcp.scanner import MCPScanner
from suscheck.modules.repo.scanner import RepoScanner
from suscheck.modules.supply_chain.auditor import SupplyChainAuditor
from suscheck.modules.external.engine import Tier0Engine
from suscheck.ai.triage_engine import run_ai_triage

class ScanPipeline:
    """Orchestrates complex scan workflows like recursive directory traversal."""

    def __init__(self, config: Optional["ConfigManager"] = None):
        self.config = config
        self.detector = AutoDetector(config=config)
        self.aggregator = RiskAggregator()
        self.supply_chain_auditor = SupplyChainAuditor()
        self.repo_scanner = RepoScanner()
        self.code_scanner = CodeScanner()
        self.config_scanner = ConfigScanner()
        self.tier0_engine = Tier0Engine()
        
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

    def scan_directory(self, target_dir: str) -> List[Finding]:
        """Recursive scan helper as expected by CLI."""
        target_path = Path(target_dir).resolve()
        findings: List[Finding] = []
        
        # --- Tier 1: Repository-Level Orchestration ---
        repo_res = self.repo_scanner.scan(str(target_path))
        findings.extend(repo_res.findings)
        
        # --- Tier 1: Recursive File Analysis ---
        files_to_scan = []
        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [d for d in dirs if d not in self.ignore_dirs]
            for f in files:
                files_to_scan.append(Path(root) / f)

        for p in files_to_scan:
            try:
                # Tier 0: Hash & Reputation
                t0_res = self.tier0_engine.check_file(str(p))
                findings.extend(t0_res.findings)
                
                # Direct dispatch based on Auto-Detector
                file_findings = self.scan_single_file(p)
                findings.extend(file_findings)
            except Exception:
                continue
                
        return findings

    def scan_project(self, target_dir: str, dynamic_mcp: bool = False, ai_triage: bool = True) -> Dict[str, Any]:
        """Performs a Unified Forensic Scan and returns a summary report."""
        start_time = time.time()
        target_path = Path(target_dir).resolve()
        
        findings = self.scan_directory(target_dir)

        # --- Tier 2: Unified AI Triage ---
        ai_delta = 0.0
        if ai_triage and findings:
            triage_res = run_ai_triage(findings, target=str(target_path), artifact_type="REPOSITORY")
            ai_delta = triage_res.pri_adjustment

        # --- Tier 3: Unified Risk Aggregation ---
        pri_result = self.aggregator.calculate(
            findings=findings,
            ai_pri_delta=ai_delta
        )

        return {
            "findings": findings,
            "pri": pri_result,
            "duration": time.time() - start_time,
            "artifact_info": {
                "path": str(target_path),
                "type": "REPOSITORY",
                "file_count": len(list(target_path.rglob('*'))) # Simplified for count
            }
        }

    def scan_single_file(self, path: Path, dynamic_mcp: bool = False) -> List[Finding]:
        """Detect and scan a single file based on its type."""
        findings: List[Finding] = []
        det = self.detector.detect(str(path))
        
        if det.type_mismatch:
            findings.append(
                Finding(
                    module="auto-detector",
                    finding_id="FILE-TYPE-MISMATCH",
                    title="File Type Mismatch (Masquerading Detected T1036.008)",
                    description=det.mismatch_detail or "File type mismatch detected.",
                    severity=Severity.HIGH,
                    finding_type=FindingType.FILE_MISMATCH,
                    confidence=1.0,
                    file_path=str(path),
                    mitre_ids=["T1036.008"]
                )
            )

        if det.artifact_type in [ArtifactType.CODE, ArtifactType.UNKNOWN] or det.type_mismatch:
            res = self.code_scanner.scan_file(str(path), language=det.language.value)
            findings.extend(res.findings)
            
            # Shadow Dependency Detection
            if det.language in [Language.PYTHON, Language.JAVASCRIPT]:
                shadow_findings = self.supply_chain_auditor.scan_source_imports(str(path))
                findings.extend(shadow_findings)
                
            # If still no findings and it's unknown/text, try secret scan as fallback
            if not findings and det.language in [Language.UNKNOWN, Language.TEXT]:
                secret_findings = self.repo_scanner.scan_file_secrets(str(path))
                findings.extend(secret_findings)
                
        elif det.artifact_type == ArtifactType.CONFIG:
            res = self.config_scanner.scan(str(path))
            findings.extend(res.findings)
        
        elif det.artifact_type == ArtifactType.UNKNOWN and path.is_file():
            # Fallback for unknown files - at least check for secrets
            res = self.repo_scanner.scan_file_secrets(str(path))
            findings.extend(res)
            
        elif det.artifact_type == ArtifactType.MCP_SERVER:
            # Static check
            s_scanner = MCPScanner()
            res = s_scanner.scan(str(path))
            findings.extend(res.findings)
        
        return findings
