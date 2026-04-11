"""TOML Language Plugin Loader (Layer 2).

Dynamically loads language-specific threat patterns from TOML files
in the `rules/` directory and executes them against the provided content.
Replaces the hardcoded regex dictionaries from earlier increments.
"""

import logging
import re
import sys
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from suscheck.core.finding import Finding, FindingType, Severity

logger = logging.getLogger(__name__)

def load_rules(language: str) -> list[dict[str, Any]]:
    """Load TOML rules for the given language, plus universal rules.
    
    Args:
        language: The detected language of the file.
        
    Returns:
        List of parsed rule dictionaries.
    """
    # Find the rules directory (assuming suscheck/rules relative to project root)
    # The clean way is to search relative to package base or cwd.
    project_root = Path(__file__).parent.parent.parent.parent.parent
    rules_dir = project_root / "rules"
    
    # If running normally without full repo context, fallback to cwd/rules
    if not rules_dir.exists():
        rules_dir = Path("rules")
        
    if not rules_dir.exists() or not rules_dir.is_dir():
        logger.debug(f"Rules directory not found at {rules_dir}")
        return []

    rules = []
    # Always attempt to load universal rules
    target_files = ["universal.toml"]
    
    if language and language.lower() != "unknown":
        target_files.append(f"{language.lower()}.toml")
        
        # Add special aliases
        if language.lower() in ("bash", "shell", "sh"):
            target_files.append("bash.toml")
        elif language.lower() in ("bat", "batch", "cmd"):
            target_files.append("batch.toml")

    # Deduplicate preserving order
    target_files = list(dict.fromkeys(target_files))

    for filename in target_files:
        rule_path = rules_dir / filename
        if not rule_path.exists():
            continue
            
        try:
            with open(rule_path, "rb") as f:
                data = tomllib.load(f)
                if "rules" in data:
                    for rule in data["rules"]:
                        # Pre-compile the regex
                        try:
                            rule["_compiled"] = re.compile(rule["regex"])
                            rules.append(rule)
                        except re.error as e:
                            logger.error(f"Failed to compile regex in {filename} rule {rule.get('id')}: {e}")
        except Exception as e:
            logger.error(f"Failed to load TOML rule file {rule_path}: {e}")

    return rules


def detect_plugins(
    content: str, file_path: str = "", language: str = "unknown"
) -> list[Finding]:
    """Scan file content using dynamically loaded TOML plugins.

    Args:
        content: File content as string.
        file_path: Path to file (for finding metadata).
        language: Detected language (used to filter language-specific patterns).

    Returns:
        List of Finding objects.
    """
    findings = []
    lines = content.split("\n")
    
    rules = load_rules(language)
    if not rules:
        return findings

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue

        for rule in rules:
            if rule["_compiled"].search(line):
                
                # Parse finding type securely
                try:
                    finding_type = FindingType(rule.get("finding_type", "suspicious_behavior"))
                except ValueError:
                    finding_type = FindingType.SUSPICIOUS_BEHAVIOR

                # Parse severity securely
                try:
                    severity = Severity(rule.get("severity", "high").lower())
                except ValueError:
                    severity = Severity.HIGH

                findings.append(Finding(
                    module="code_scanner.plugin_loader",
                    finding_id=f"{rule.get('id', 'PLUGIN-UNKNOWN')}-{line_num:04d}",
                    title=rule.get("name", "Dangerous Pattern"),
                    description=rule.get("description", "A dangerous pattern was detected by a dynamic plugin."),
                    severity=severity,
                    finding_type=finding_type,
                    confidence=float(rule.get("confidence", 0.5)),
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=stripped[:200],
                    mitre_ids=rule.get("mitre_ids", []),
                    evidence={
                        "pattern_id": rule.get("id"),
                        "detected_language": language,
                    },
                ))

    return findings
