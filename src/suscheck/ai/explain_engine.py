"""AI behavioral explanation engine — plain English deep-dives (Increment 17)."""

import logging
from typing import List, Optional
from suscheck.ai.factory import create_ai_provider
from suscheck.core.finding import Finding

logger = logging.getLogger(__name__)

EXPLAIN_SYSTEM_PROMPT = """You are a Senior Security Architect and Malware Analyst.
Your goal is to explain a file's behavior in plain English for a developer who may not be a security expert.

You will be provided with:
1. File Metadata (Target, Type)
2. Automated Scan Findings (Hints from static analysis tools)
3. Raw File Content (Code or binary representation)

Your response MUST be formatted in clean Markdown with the following sections:

### 🎯 Behavioral Summary
Explain in 2-3 sentences what this file is trying to accomplish. What is its primary intent?

### 🔍 Risk Analysis
Analyze why the automated scanners flagged this file. 
For each major finding provided:
- Explain the technical risk.
- Identify if it looks like a legitimate administrative action or a malicious evasion technique.

### 🛡️ Safety Verdict
Provide a clear recommendation:
- **SAFE**: Benign code, likely a false positive flag.
- **CAUTION**: Legitimate code with risky capabilities (e.g. powerful system modifications) that should be audited manually.
- **DANGEROUS**: High confidence of malicious intent (backdoors, data exfiltration, obfuscated droppers).

### 💡 Recommendation
What should the developer do next? (e.g., "Safe to run", "Check the destination URL in line 45", "DO NOT EXECUTE").

Keep your explanation objective, professional, and technical but accessible. Avoid hyperbole.
"""

def _format_findings_for_ai(findings: List[Finding]) -> str:
    if not findings:
        return "No automated findings reported."
    
    lines = []
    for f in findings:
        lines.append(f"- [{f.severity.value.upper()}] {f.title}: {f.description}")
    return "\n".join(lines)

def run_behavioral_analysis(
    target: str,
    artifact_type: str,
    findings: List[Finding],
    file_content: str,
    console: Optional[object] = None
) -> str:
    """Orchestrate the AI explanation flow."""
    provider = create_ai_provider()
    
    if not provider.is_configured():
        return (
            "⚠️ AI Explanation is unavailable because no AI provider is configured. "
            "Please set SUSCHECK_AI_PROVIDER and provider API key env vars (or SUSCHECK_AI_KEY)."
        )

    # Limit file content to prevent token overflow (~32k characters / 8k-10k tokens)
    # This is a safe baseline for most models.
    safe_content = file_content[:32000]
    if len(file_content) > 32000:
        safe_content += "\n\n[... content truncated for brevity ...]"

    findings_text = _format_findings_for_ai(findings)

    user_prompt = f"""Target: {target}
Artifact Type: {artifact_type}

--- SCAN FINDINGS (Context) ---
{findings_text}

--- FILE CONTENT ---
{safe_content}
"""

    try:
        if console:
            console.print(f"  [dim]Behavioral AI ({provider.name}) performing deep analysis...[/dim]")

        explanation = provider.complete_narrative(
            system_prompt=EXPLAIN_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            timeout_sec=150
        )
        return explanation
    except Exception as e:
        logger.exception("AI explanation failed")
        return f"❌ AI Explanation failed: {str(e)}"
