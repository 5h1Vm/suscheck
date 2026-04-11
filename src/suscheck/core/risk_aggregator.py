"""Platform Risk Index (PRI) Scoring Engine.

Implements the 10-step algorithm for aggregating security findings
from all modules, applying correlation bonuses, context multipliers,
and generating a final 0-100 score and verdict.
"""

from dataclasses import dataclass, field
from typing import Any

from suscheck.core.finding import Finding, FindingType, Severity, Verdict


@dataclass
class PRIScore:
    """The final calculated Platform Risk Index score and explanation."""
    score: int
    verdict: Verdict
    breakdown: list[str] = field(default_factory=list)


class RiskAggregator:
    """Aggregates findings into a single Platform Risk Index score."""

    # Severity base points definition
    _SEVERITY_POINTS = {
        Severity.CRITICAL: 25,
        Severity.HIGH: 15,
        Severity.MEDIUM: 8,
        Severity.LOW: 3,
        Severity.INFO: 1,  # INFO represents 1 point per checkpoint definition
    }

    # Internal finding IDs that do not contribute to score
    _NEUTRAL_FINDING_IDS = {
        "VT-CLEAN-001",
        "VT-NOTFOUND-001",
    }

    def __init__(self, artifact_type: str = "CODE"):
        self.artifact_type = artifact_type.upper()

    def calculate(self, findings: list[Finding], vt_result: dict | None = None) -> PRIScore:
        """Calculate the 10-step PRI score from findings."""
        score = 0.0
        breakdown = []
        breakdown.append("[bold]Score Breakdown:[/bold]")

        # ── Step 1 & 2: Base Scoring ──────────────────────────────────────────
        base_score = 0.0
        contributing_findings = []
        for f in findings:
            if f.ai_false_positive or f.finding_id in self._NEUTRAL_FINDING_IDS:
                continue

            base = self._SEVERITY_POINTS.get(f.severity, 0)
            points = base * f.confidence
            base_score += points
            contributing_findings.append(f)
            
            # Format title up to 60 chars properly
            short_title = f.title if len(f.title) < 60 else f"{f.title[:57]}..."
            breakdown.append(
                f"  [dim]•[/dim] {short_title} → "
                f"{base} pts × {f.confidence:.2f} conf = [bold]{points:.1f}[/bold] pts"
            )

        if not contributing_findings:
            breakdown.append("  [dim]•[/dim] No risk-contributing base findings.")

        score += base_score

        # ── Step 3: Context Multiplier ────────────────────────────────────────
        context_multiplier = 1.0
        ctx_reason = "general code"
        
        # Determine context multiplier
        if "script" in self.artifact_type.lower() or "sh" in self.artifact_type.lower():
            context_multiplier = 1.5
            ctx_reason = "install/execution script"
        elif "package" in self.artifact_type.lower():
            context_multiplier = 1.4
            ctx_reason = "dependency package"
            
        if context_multiplier != 1.0:
            adjustment = score * context_multiplier - score
            score *= context_multiplier
            breakdown.append(f"  [yellow]⚡ Context Multiplier ({ctx_reason})[/yellow] → x{context_multiplier} (added [bold]{adjustment:.1f}[/bold] pts)")

        # ── Step 4: Correlation Bonuses ───────────────────────────────────────
        correlation_score = 0.0
        
        # Gather states
        has_network = any(f.finding_type in (FindingType.NETWORK_INDICATOR, FindingType.C2_INDICATOR) for f in findings)
        has_obfuscation = any(f.finding_type in (FindingType.ENCODED_PAYLOAD, FindingType.FILE_MISMATCH, FindingType.POLYGLOT) for f in findings)
        has_execution = any(f.finding_type == FindingType.SUSPICIOUS_BEHAVIOR for f in findings)
        has_secrets = any(f.finding_type == FindingType.SECRET_EXPOSURE for f in findings)
        
        # Check EVASION_ATTEMPT (Obfuscation + malicious execution/network)
        if has_obfuscation and (has_network or has_execution):
            correlation_score += 15.0
            breakdown.append("  [red]🔥 Correlation: Evasion Attempt[/red] (Obfuscation + Network/Execution) → +[bold]15.0[/bold] pts")

        # Check STAGED_ATTACK (Network + execution)
        if has_network and has_execution:
            correlation_score += 30.0
            breakdown.append("  [red]🔥 Correlation: Staged Attack[/red] (Network download + Execution) → +[bold]30.0[/bold] pts")

        score += correlation_score

        # ── Step 5: Supply Chain Trust Score Multiplier ───────────────────────
        # To be implemented in Increment 9. For now, 1.0x.
        trust_multiplier = 1.0

        # ── Step 6: VirusTotal Adjustments ────────────────────────────────────
        vt_adjustment = 0.0
        if vt_result and vt_result.get("status") == "found":
            stats = vt_result["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0) + stats.get("suspicious", 0)
            
            if malicious == 0:
                vt_adjustment = -5.0
                breakdown.append("  [green]🛡️ VirusTotal Clean[/green] (0 detections) → [bold]-5.0[/bold] pts")
            elif 1 <= malicious <= 3:
                vt_adjustment = 10.0
                breakdown.append(f"  [red]⚠️ VirusTotal Suspicious[/red] ({malicious} detections) → +[bold]10.0[/bold] pts")
            elif 4 <= malicious <= 10:
                vt_adjustment = 25.0
                breakdown.append(f"  [red]🚨 VirusTotal Malicious[/red] ({malicious} detections) → +[bold]25.0[/bold] pts")
            elif 11 <= malicious <= 25:
                vt_adjustment = 40.0
                breakdown.append(f"  [red]🚨 VirusTotal Critical[/red] ({malicious} detections) → +[bold]40.0[/bold] pts")
            else:
                vt_adjustment = 60.0
                breakdown.append(f"  [red]🚨 VirusTotal Extreme[/red] ({malicious} detections) → +[bold]60.0[/bold] pts")
                
        score += vt_adjustment
        
        # ── Step 7: AI Adjustment ─────────────────────────────────────────────
        # To be implemented with external LLM triage

        # ── Step 8: Normalize (Clamp to 0-100) ────────────────────────────────
        score_int = int(score)
        final_score = max(0, min(100, score_int))
        
        raw_score_str = f" (raw: {score_int})" if score_int > 100 or score_int < 0 else ""
        breakdown.append(f"  [bold]Total Score: {final_score}/100{raw_score_str}[/bold]")

        # Add informational items at the end
        info_findings = [f for f in findings if f.severity == Severity.INFO or f.finding_id in self._NEUTRAL_FINDING_IDS]
        if info_findings:
            breakdown.append("")
            breakdown.append("[dim]Informational (not scored):[/dim]")
            for f in info_findings:
                breakdown.append(f"  [dim]• {f.title}[/dim]")

        # ── Step 9: Verdict ───────────────────────────────────────────────────
        if final_score <= 15:
            verdict = Verdict.CLEAR
        elif final_score <= 40:
            verdict = Verdict.CAUTION
        elif final_score <= 70:
            verdict = Verdict.HOLD
        else:
            verdict = Verdict.ABORT

        return PRIScore(score=final_score, verdict=verdict, breakdown=breakdown)
