"""Quick demo to test the terminal output renderer."""

from suscheck.core.finding import Finding, ScanSummary, Severity, FindingType, Verdict
from suscheck.output.terminal import (
    render_scan_header,
    render_verdict,
    render_findings,
    render_vt_result,
    render_scan_footer,
)

# Create fake findings to test the display
findings = [
    Finding(
        module="code_scanner",
        finding_id="C2-BASE64-001",
        title="Base64-encoded C2 URL detected",
        description="Decoded base64 string reveals URL http://45.33.xx.xx:4444/beacon",
        severity=Severity.CRITICAL,
        finding_type=FindingType.C2_COMMUNICATION,
        confidence=0.95,
        file_path="malware.py",
        line_number=47,
        code_snippet='payload = base64.b64decode("aHR0cDovLzQ1LjMz...")',
        mitre_ids=["T1071.001", "T1132.001"],
    ),
    Finding(
        module="code_scanner",
        finding_id="SHELL-001",
        title="Reverse shell pattern detected",
        description="Socket connection to external IP on port 4444 with subprocess pipe",
        severity=Severity.CRITICAL,
        finding_type=FindingType.REVERSE_SHELL,
        confidence=0.90,
        file_path="malware.py",
        line_number=52,
        mitre_ids=["T1059.006"],
    ),
    Finding(
        module="secret_scanner",
        finding_id="SECRET-001",
        title="Hardcoded API key detected",
        description="AWS access key pattern found in source code",
        severity=Severity.HIGH,
        finding_type=FindingType.SECRET_EXPOSURE,
        confidence=0.85,
        file_path="config.py",
        line_number=12,
    ),
    Finding(
        module="code_scanner",
        finding_id="ENTROPY-001",
        title="High-entropy string detected",
        description="Unrecognized high-entropy block, could be encrypted payload or legitimate hash",
        severity=Severity.MEDIUM,
        finding_type=FindingType.REVIEW_NEEDED,
        confidence=0.60,
        file_path="utils.py",
        line_number=78,
        needs_human_review=True,
        review_reason="Automated decoding failed. String entropy is 7.2/8.0. Could be encrypted config or obfuscated payload.",
    ),
    Finding(
        module="config_scanner",
        finding_id="CFG-001",
        title="Debug mode enabled",
        description="DEBUG=True found in configuration",
        severity=Severity.LOW,
        finding_type=FindingType.CONFIG_RISK,
        confidence=1.0,
        file_path=".env",
        line_number=3,
    ),
]

# Build summary
summary = ScanSummary(
    target="suspicious_project/",
    artifact_type="repository",
    pri_score=78,
    verdict=Verdict.ABORT,
    findings=findings,
    total_findings=len(findings),
    critical_count=2,
    high_count=1,
    medium_count=1,
    low_count=1,
    info_count=0,
    review_count=1,
    scan_duration=3.45,
    modules_ran=["code_scanner", "secret_scanner", "config_scanner"],
    modules_skipped=["supply_chain (no package)", "mcp (not mcp target)"],
    trust_score=2.5,
)

vt_result = {
    "found": True,
    "detection_count": 12,
    "total_engines": 70,
    "detection_names": ["Trojan.Python.Agent", "Backdoor.Shell.Rev", "Malware.Generic"],
    "vt_link": "https://www.virustotal.com/gui/file/abc123...",
}

# Render everything
render_scan_header("suspicious_project/", "repository", "0.1.0")
render_vt_result(vt_result)
render_verdict(summary)
render_findings(findings)
render_scan_footer(summary)
