"""Dangerous Function Detector — cross-language threat pattern detection.

Detects dangerous function calls, command execution, and code injection
patterns across multiple languages. Focuses on THREAT patterns
(C2, shells, malware, obfuscation), NOT vulnerability patterns
(that's Semgrep's job per the spec).
"""

import logging
import re
from dataclasses import dataclass

from suscheck.core.finding import Finding, FindingType, Severity

logger = logging.getLogger(__name__)


@dataclass
class DangerousPattern:
    """A dangerous function/pattern to detect."""
    pattern_id: str
    name: str
    regex: re.Pattern
    severity: Severity
    confidence: float
    languages: list[str]      # Which languages this applies to ("*" = all)
    description: str
    mitre_ids: list[str]
    finding_type: FindingType = FindingType.SUSPICIOUS_BEHAVIOR


# ── Pattern definitions ────────────────────────────────────────────
DANGEROUS_PATTERNS: list[DangerousPattern] = [
    # ═══════════════════════════════════════════════════════
    # UNIVERSAL (any language)
    # ═══════════════════════════════════════════════════════
    DangerousPattern(
        pattern_id="FUNC-EVAL",
        name="eval() call",
        regex=re.compile(r'\beval\s*\(', re.IGNORECASE),
        severity=Severity.HIGH,
        confidence=0.70,
        languages=["*"],
        description="eval() executes arbitrary code. Commonly used in malware to run decoded/downloaded payloads.",
        mitre_ids=["T1059"],  # Command and Scripting Interpreter
    ),
    DangerousPattern(
        pattern_id="FUNC-EXEC",
        name="exec() call",
        regex=re.compile(r'\bexec\s*\(', re.IGNORECASE),
        severity=Severity.HIGH,
        confidence=0.65,
        languages=["*"],
        description="exec() executes arbitrary code. Often used to run obfuscated malicious payloads.",
        mitre_ids=["T1059"],
    ),
    DangerousPattern(
        pattern_id="FUNC-SYSTEM",
        name="system() call",
        regex=re.compile(r'\bsystem\s*\(', re.IGNORECASE),
        severity=Severity.HIGH,
        confidence=0.65,
        languages=["*"],
        description="system() executes OS commands. Can be used for command injection, reverse shells, or data exfiltration.",
        mitre_ids=["T1059", "T1106"],
    ),

    # ═══════════════════════════════════════════════════════
    # PYTHON
    # ═══════════════════════════════════════════════════════
    DangerousPattern(
        pattern_id="FUNC-PY-IMPORT",
        name="Dynamic __import__",
        regex=re.compile(r'__import__\s*\('),
        severity=Severity.MEDIUM,
        confidence=0.55,
        languages=["python"],
        description="__import__() dynamically imports modules. Often used to obfuscate malicious imports.",
        mitre_ids=["T1059.006"],
    ),
    DangerousPattern(
        pattern_id="FUNC-PY-SUBPROCESS",
        name="subprocess usage",
        regex=re.compile(r'subprocess\s*\.\s*(?:call|run|Popen|check_output|check_call)\s*\('),
        severity=Severity.MEDIUM,
        confidence=0.50,
        languages=["python"],
        description="subprocess executes OS commands. Check if the command is from user input or hardcoded.",
        mitre_ids=["T1059.006"],
    ),
    DangerousPattern(
        pattern_id="FUNC-PY-OS-SYSTEM",
        name="os.system() call",
        regex=re.compile(r'os\s*\.\s*system\s*\('),
        severity=Severity.HIGH,
        confidence=0.65,
        languages=["python"],
        description="os.system() executes shell commands. Dangerous if input is not sanitized.",
        mitre_ids=["T1059.006"],
    ),
    DangerousPattern(
        pattern_id="FUNC-PY-PICKLE",
        name="pickle.loads() — deserialization",
        regex=re.compile(r'pickle\s*\.\s*(?:loads?|Unpickler)\s*\('),
        severity=Severity.HIGH,
        confidence=0.70,
        languages=["python"],
        description="pickle deserialization can execute arbitrary code. A common Python exploitation vector.",
        mitre_ids=["T1059.006", "T1203"],
    ),
    DangerousPattern(
        pattern_id="FUNC-PY-COMPILE",
        name="compile() with exec",
        regex=re.compile(r'compile\s*\([^)]*["\']exec["\']'),
        severity=Severity.HIGH,
        confidence=0.70,
        languages=["python"],
        description="compile() with 'exec' mode can compile and execute arbitrary code.",
        mitre_ids=["T1059.006"],
    ),
    DangerousPattern(
        pattern_id="FUNC-PY-SOCKET",
        name="Raw socket creation",
        regex=re.compile(r'socket\s*\.\s*socket\s*\('),
        severity=Severity.MEDIUM,
        confidence=0.40,
        languages=["python"],
        description="Raw socket creation. Could be used for reverse shells or network communication.",
        mitre_ids=["T1071"],
    ),

    # ═══════════════════════════════════════════════════════
    # JAVASCRIPT
    # ═══════════════════════════════════════════════════════
    DangerousPattern(
        pattern_id="FUNC-JS-EVAL-ATOB",
        name="eval(atob()) — decode and execute",
        regex=re.compile(r'eval\s*\(\s*atob\s*\('),
        severity=Severity.CRITICAL,
        confidence=0.90,
        languages=["javascript"],
        description="eval(atob()) decodes base64 and immediately executes it. Classic malware pattern.",
        mitre_ids=["T1059.007", "T1140"],
        finding_type=FindingType.ENCODED_PAYLOAD,
    ),
    DangerousPattern(
        pattern_id="FUNC-JS-FUNCTION",
        name="Function() constructor",
        regex=re.compile(r'(?:new\s+)?Function\s*\('),
        severity=Severity.HIGH,
        confidence=0.65,
        languages=["javascript"],
        description="Function constructor creates functions from strings, equivalent to eval().",
        mitre_ids=["T1059.007"],
    ),
    DangerousPattern(
        pattern_id="FUNC-JS-SETTIMEOUT-STR",
        name="setTimeout() with string",
        regex=re.compile(r'setTimeout\s*\(\s*["\']'),
        severity=Severity.MEDIUM,
        confidence=0.60,
        languages=["javascript"],
        description="setTimeout() with a string argument acts as eval(). Can execute arbitrary code.",
        mitre_ids=["T1059.007"],
    ),

    # ═══════════════════════════════════════════════════════
    # POWERSHELL
    # ═══════════════════════════════════════════════════════
    DangerousPattern(
        pattern_id="FUNC-PS-IEX",
        name="Invoke-Expression (IEX)",
        regex=re.compile(r'(?:Invoke-Expression|IEX)\b', re.IGNORECASE),
        severity=Severity.HIGH,
        confidence=0.80,
        languages=["powershell"],
        description="Invoke-Expression (IEX) executes arbitrary PowerShell. Core component of most PS exploits.",
        mitre_ids=["T1059.001"],
    ),
    DangerousPattern(
        pattern_id="FUNC-PS-WEBCLIENT",
        name="Net.WebClient download",
        regex=re.compile(
            r'(?:Net\.WebClient|WebClient|Invoke-WebRequest|Invoke-RestMethod|'
            r'wget\b|curl\b|iwr\b|irm\b)',
            re.IGNORECASE,
        ),
        severity=Severity.MEDIUM,
        confidence=0.55,
        languages=["powershell"],
        description="Web download in PowerShell. Check if it downloads and executes content.",
        mitre_ids=["T1059.001", "T1105"],
    ),
    DangerousPattern(
        pattern_id="FUNC-PS-ENCODED-CMD",
        name="PowerShell -EncodedCommand",
        regex=re.compile(r'-(?:enc|encodedcommand)\b', re.IGNORECASE),
        severity=Severity.HIGH,
        confidence=0.85,
        languages=["powershell"],
        description="PowerShell -EncodedCommand executes base64-encoded scripts. Heavily used by malware.",
        mitre_ids=["T1059.001", "T1027"],
    ),
    DangerousPattern(
        pattern_id="FUNC-PS-AMSI",
        name="AMSI bypass attempt",
        regex=re.compile(
            r'(?:amsiInitFailed|AmsiUtils|amsi\.dll|AmsiScanBuffer)',
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
        confidence=0.90,
        languages=["powershell"],
        description="AMSI (Antimalware Scan Interface) bypass attempt detected. Strong malware indicator.",
        mitre_ids=["T1562.001"],  # Impair Defenses: Disable/Modify Tools
        finding_type=FindingType.EVASION,
    ),
    DangerousPattern(
        pattern_id="FUNC-PS-EXECUTION-POLICY",
        name="Execution policy bypass",
        regex=re.compile(r'-ExecutionPolicy\s+(?:Bypass|Unrestricted)', re.IGNORECASE),
        severity=Severity.MEDIUM,
        confidence=0.65,
        languages=["powershell"],
        description="PowerShell execution policy bypass. Common in malware droppers.",
        mitre_ids=["T1059.001"],
    ),

    # ═══════════════════════════════════════════════════════
    # BASH / SHELL
    # ═══════════════════════════════════════════════════════
    DangerousPattern(
        pattern_id="FUNC-SH-CURL-PIPE",
        name="curl | bash (download and execute)",
        regex=re.compile(r'curl\s+[^|]*\|\s*(?:ba)?sh', re.IGNORECASE),
        severity=Severity.CRITICAL,
        confidence=0.85,
        languages=["bash", "shell"],
        description="Download and execute pattern. Fetches remote code and runs it directly.",
        mitre_ids=["T1059.004", "T1105"],
        finding_type=FindingType.SUSPICIOUS_BEHAVIOR,
    ),
    DangerousPattern(
        pattern_id="FUNC-SH-WGET-PIPE",
        name="wget | sh (download and execute)",
        regex=re.compile(r'wget\s+[^|]*\|\s*(?:ba)?sh', re.IGNORECASE),
        severity=Severity.CRITICAL,
        confidence=0.85,
        languages=["bash", "shell"],
        description="Download and execute pattern via wget. Fetches remote code and runs it directly.",
        mitre_ids=["T1059.004", "T1105"],
        finding_type=FindingType.SUSPICIOUS_BEHAVIOR,
    ),
    DangerousPattern(
        pattern_id="FUNC-SH-REVERSE-SHELL",
        name="Reverse shell (nc/ncat)",
        regex=re.compile(r'(?:nc|ncat|netcat)\s+.{0,200}-e\s+/bin/(?:ba)?sh', re.IGNORECASE),
        severity=Severity.CRITICAL,
        confidence=0.95,
        languages=["bash", "shell"],
        description="Netcat reverse shell detected. Opens a remote command shell.",
        mitre_ids=["T1059.004", "T1071.001"],
        finding_type=FindingType.C2_INDICATOR,
    ),
    DangerousPattern(
        pattern_id="FUNC-SH-CRON-PERSIST",
        name="Cron persistence",
        regex=re.compile(r'(?:crontab|/etc/cron)', re.IGNORECASE),
        severity=Severity.MEDIUM,
        confidence=0.50,
        languages=["bash", "shell"],
        description="Cron job manipulation detected. Can be used for persistence.",
        mitre_ids=["T1053.003"],  # Scheduled Task/Job: Cron
    ),

    # ═══════════════════════════════════════════════════════
    # BATCH / CMD
    # ═══════════════════════════════════════════════════════
    DangerousPattern(
        pattern_id="FUNC-BAT-POWERSHELL",
        name="Batch → PowerShell execution",
        regex=re.compile(r'powershell(?:\.exe)?\s+.{0,200}-[eE](?:nc)?', re.IGNORECASE),
        severity=Severity.HIGH,
        confidence=0.80,
        languages=["batch"],
        description="Batch file launching PowerShell with encoded command. Classic dropper pattern.",
        mitre_ids=["T1059.003", "T1059.001"],
    ),
    DangerousPattern(
        pattern_id="FUNC-BAT-REG",
        name="Registry modification",
        regex=re.compile(r'\breg\s+(?:add|delete)\b', re.IGNORECASE),
        severity=Severity.MEDIUM,
        confidence=0.50,
        languages=["batch"],
        description="Registry modification via reg.exe. Can be used for persistence or defense evasion.",
        mitre_ids=["T1112"],  # Modify Registry
    ),
    DangerousPattern(
        pattern_id="FUNC-BAT-SC",
        name="Service manipulation",
        regex=re.compile(r'\bsc\s+(?:create|config|start|stop|delete)\b', re.IGNORECASE),
        severity=Severity.MEDIUM,
        confidence=0.50,
        languages=["batch"],
        description="Windows service manipulation. Can be used for persistence or privilege escalation.",
        mitre_ids=["T1543.003"],  # Create or Modify System Service
    ),
    DangerousPattern(
        pattern_id="FUNC-BAT-SCHTASKS",
        name="Scheduled task creation",
        regex=re.compile(r'\bschtasks\s+/create\b', re.IGNORECASE),
        severity=Severity.MEDIUM,
        confidence=0.55,
        languages=["batch"],
        description="Scheduled task creation. Often used for persistence.",
        mitre_ids=["T1053.005"],  # Scheduled Task
    ),
    DangerousPattern(
        pattern_id="FUNC-BAT-WEVTUTIL",
        name="Event log clearing",
        regex=re.compile(r'\bwevtutil\s+(?:cl|clear-log)\b', re.IGNORECASE),
        severity=Severity.HIGH,
        confidence=0.70,
        languages=["batch"],
        description="Windows Event Log clearing. Defense evasion technique to hide tracks.",
        mitre_ids=["T1070.001"],  # Clear Windows Event Logs
    ),
    DangerousPattern(
        pattern_id="FUNC-BAT-NETSH",
        name="Firewall rule modification",
        regex=re.compile(r'\bnetsh\s+(?:advfirewall|firewall)\b', re.IGNORECASE),
        severity=Severity.MEDIUM,
        confidence=0.50,
        languages=["batch"],
        description="Firewall rule modification via netsh. Can be used to open backdoor ports.",
        mitre_ids=["T1562.004"],  # Impair Defenses: Disable or Modify Firewall
    ),
    DangerousPattern(
        pattern_id="FUNC-BAT-NET-STOP",
        name="Service stop command",
        regex=re.compile(r'\bnet\s+stop\s+\w+', re.IGNORECASE),
        severity=Severity.LOW,
        confidence=0.35,
        languages=["batch"],
        description="Stopping a Windows service. Could be disabling security tools.",
        mitre_ids=["T1489"],  # Service Stop
    ),
    DangerousPattern(
        pattern_id="FUNC-BAT-CACLS",
        name="ACL/permission modification",
        regex=re.compile(r'\b(?:cacls|icacls|takeown)\b', re.IGNORECASE),
        severity=Severity.MEDIUM,
        confidence=0.45,
        languages=["batch"],
        description="File permission/ACL modification. Can be used for privilege escalation.",
        mitre_ids=["T1222.001"],  # File and Directory Permissions Modification
    ),
    DangerousPattern(
        pattern_id="FUNC-BAT-UAC-BYPASS",
        name="UAC elevation request",
        regex=re.compile(r'(?:ShellExecute.*runas|runas\s+/user)', re.IGNORECASE),
        severity=Severity.MEDIUM,
        confidence=0.60,
        languages=["batch"],
        description="UAC elevation attempt. Requesting admin privileges.",
        mitre_ids=["T1548.002"],  # Bypass User Account Control
    ),

    # ═══════════════════════════════════════════════════════
    # PHP
    # ═══════════════════════════════════════════════════════
    DangerousPattern(
        pattern_id="FUNC-PHP-PASSTHRU",
        name="PHP passthru/shell_exec",
        regex=re.compile(r'\b(?:passthru|shell_exec|proc_open|popen)\s*\('),
        severity=Severity.HIGH,
        confidence=0.70,
        languages=["php"],
        description="PHP command execution function. Can run arbitrary OS commands.",
        mitre_ids=["T1059"],
    ),
    DangerousPattern(
        pattern_id="FUNC-PHP-PREG-E",
        name="PHP preg_replace /e modifier",
        regex=re.compile(r'preg_replace\s*\(\s*["\'][^"\']*\/e[imsxuU]*["\']'),
        severity=Severity.CRITICAL,
        confidence=0.85,
        languages=["php"],
        description="preg_replace with /e modifier executes the replacement as PHP code. Classic webshell pattern.",
        mitre_ids=["T1059"],
    ),

    # ═══════════════════════════════════════════════════════
    # JAVA
    # ═══════════════════════════════════════════════════════
    DangerousPattern(
        pattern_id="FUNC-JAVA-RUNTIME-EXEC",
        name="Java Runtime.exec()",
        regex=re.compile(r'Runtime\s*\.\s*(?:getRuntime\s*\(\s*\)\s*\.\s*)?exec\s*\('),
        severity=Severity.HIGH,
        confidence=0.65,
        languages=["java"],
        description="Java Runtime.exec() executes OS commands. Check for command injection.",
        mitre_ids=["T1059"],
    ),
    DangerousPattern(
        pattern_id="FUNC-JAVA-PROCESSBUILDER",
        name="Java ProcessBuilder",
        regex=re.compile(r'ProcessBuilder\s*\('),
        severity=Severity.MEDIUM,
        confidence=0.50,
        languages=["java"],
        description="Java ProcessBuilder creates OS processes. Check what commands are being executed.",
        mitre_ids=["T1059"],
    ),
    DangerousPattern(
        pattern_id="FUNC-JAVA-DESERIALIZATION",
        name="Java deserialization",
        regex=re.compile(r'(?:ObjectInputStream|readObject|XMLDecoder)\s*\('),
        severity=Severity.HIGH,
        confidence=0.65,
        languages=["java"],
        description="Java deserialization detected. Can lead to Remote Code Execution (RCE).",
        mitre_ids=["T1059", "T1203"],
    ),
]


def detect_dangerous_functions(
    content: str, file_path: str = "", language: str = "unknown"
) -> list[Finding]:
    """Scan file content for dangerous function calls.

    Args:
        content: File content as string.
        file_path: Path to file (for finding metadata).
        language: Detected language (used to filter language-specific patterns).

    Returns:
        List of Finding objects for dangerous function calls.
    """
    findings = []
    lines = content.split("\n")
    language_lower = language.lower()

    # Select applicable patterns
    applicable: list[DangerousPattern] = []
    for p in DANGEROUS_PATTERNS:
        if "*" in p.languages or language_lower in p.languages or language_lower == "unknown":
            applicable.append(p)

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue

        for pattern in applicable:
            if pattern.regex.search(line):
                findings.append(Finding(
                    module="code_scanner.dangerous_functions",
                    finding_id=f"{pattern.pattern_id}-{line_num:04d}",
                    title=pattern.name,
                    description=pattern.description,
                    severity=pattern.severity,
                    finding_type=pattern.finding_type,
                    confidence=pattern.confidence,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=stripped[:200],
                    mitre_ids=pattern.mitre_ids,
                    evidence={
                        "pattern_id": pattern.pattern_id,
                        "languages": pattern.languages,
                        "detected_language": language,
                    },
                ))

    return findings
