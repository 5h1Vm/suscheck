"""Platform Risk Index (PRI) Scoring Engine.

Implements the 10-step algorithm for aggregating security findings
from all modules, applying correlation bonuses, context multipliers,
and generating a final 0-100 score and verdict.
"""

from dataclasses import dataclass, field

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
        Severity.INFO: 1,  # Aligned with Checkpoint 1a §10 Step 2
    }

    # Internal finding IDs that do not contribute to score
    _NEUTRAL_FINDING_IDS = {
        "VT-CLEAN-001",
        "VT-NOTFOUND-001",
    }

    def __init__(self, artifact_type: str = "CODE"):
        self.artifact_type = artifact_type.upper()

    def calculate(
        self,
        findings: list[Finding],
        vt_result: dict | None = None,
        ai_pri_delta: float = 0.0,
        trust_score: float | None = None,
    ) -> PRIScore:
        """Calculate the 10-step PRI score from findings."""
        score = 0.0
        breakdown = []
        breakdown.append("[bold]Score Breakdown:[/bold]")

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
        
        # Determine context multiplier (Checkpoint 1a §10 Step 3)
        if "script" in self.artifact_type.lower() or "sh" in self.artifact_type.lower():
            context_multiplier = 1.5
            ctx_reason = "install/execution script"
        elif "package" in self.artifact_type.lower():
            context_multiplier = 1.4
            ctx_reason = "dependency package"
        elif "mcp" in self.artifact_type.lower():
            context_multiplier = 1.4
            ctx_reason = "MCP server / agent tool surface"
        elif "test" in self.artifact_type.lower():
            context_multiplier = 0.5
            ctx_reason = "test file (lower risk)"
        elif "doc" in self.artifact_type.lower() or "readme" in self.artifact_type.lower():
            context_multiplier = 0.3
            ctx_reason = "documentation (minimal risk)"

        if context_multiplier != 1.0:
            adjustment = score * context_multiplier - score
            score *= context_multiplier
            breakdown.append(f"  [yellow]⚡ Context Multiplier ({ctx_reason})[/yellow] → x{context_multiplier} (added [bold]{adjustment:.1f}[/bold] pts)")

        # ── Step 4: Correlation Bonuses ───────────────────────────────────────
        correlation_score = 0.0
        
        # Gather states
        has_network = any(f.finding_type in (FindingType.NETWORK_INDICATOR, FindingType.C2_INDICATOR, FindingType.C2_COMMUNICATION) for f in findings)
        has_obfuscation = any(f.finding_type in (FindingType.ENCODED_PAYLOAD, FindingType.OBFUSCATION, FindingType.EVASION, FindingType.POLYGLOT, FindingType.FILE_MISMATCH) for f in findings)
        has_execution = any(f.finding_type in (FindingType.SUSPICIOUS_BEHAVIOR, FindingType.DANGEROUS_FUNCTION, FindingType.REVERSE_SHELL) for f in findings)
        has_typosquat = any(f.finding_type == FindingType.TYPOSQUATTING for f in findings)
        has_low_trust = trust_score is not None and trust_score < 4.0
        
        # 1. EVASION_ATTEMPT (Obfuscation + malicious execution/network) (+15)
        if has_obfuscation and (has_network or has_execution):
            correlation_score += 15.0
            breakdown.append("  [red]🔥 Correlation: Evasion Attempt[/red] (Obfuscation + Network/Execution) → +[bold]15.0[/bold] pts")

        # 2. STAGED_ATTACK (Network download + Execution) (+30)
        if has_network and has_execution:
            correlation_score += 30.0
            breakdown.append("  [red]🔥 Correlation: Staged Attack[/red] (Network download + Execution) → +[bold]30.0[/bold] pts")

        # 3. TROJAN_PACKAGE (Typosquatting + Malicious Behavior) (+25)
        if has_typosquat and (has_execution or has_network):
            correlation_score += 25.0
            breakdown.append("  [red]🔥 Correlation: Trojan Package[/red] (Typosquat + Malicious Behavior) → +[bold]25.0[/bold] pts")

        # 4. MALICIOUS_RELEASE (Low Trust + Critical Findings) (+30)
        has_critical = any(f.severity == Severity.CRITICAL for f in findings)
        if has_low_trust and has_critical:
            correlation_score += 30.0
            breakdown.append("  [red]🔥 Correlation: Malicious Release[/red] (Low Trust + Critical findings) → +[bold]30.0[/bold] pts")

        # 5. SUPPLY_CHAIN_COMPROMISE (Typosquat + Obfuscation) (+20) - Aligned with CP1a
        if has_typosquat and has_obfuscation:
            correlation_score += 20.0
            breakdown.append("  [red]🔥 Correlation: Supply Chain Compromise[/red] (Typosquat + Obfuscation) → +[bold]20.0[/bold] pts")

        # 6. COMPROMISED_REPO (Secret + Suspicious behavior) (+15)
        has_secret = any(f.finding_type == FindingType.SECRET_EXPOSURE for f in findings)
        if has_secret and (has_execution or has_network):
            correlation_score += 15.0
            breakdown.append("  [red]🔥 Correlation: Compromised Repository[/red] (Secret + Suspect Activity) → +[bold]15.0[/bold] pts")

        # 7. MCP_ATTACK (MCP Over-privilege + Lateral/Proxy signals) (+25)
        has_mcp_risk = any(f.finding_type == FindingType.MCP_OVERPRIVILEGE for f in findings)
        if has_mcp_risk and (has_network or has_obfuscation):
            correlation_score += 25.0
            breakdown.append("  [red]🔥 Correlation: MCP Attack Pattern[/red] (MCP Risk + Network/Evasion) → +[bold]25.0[/bold] pts")

        score += correlation_score

        # ── Step 5: Supply Chain Trust Score Multiplier ───────────────────────
        # Map TrustEngine's 0–10 score into a gentle PRI multiplier.
        # - Medium trust (~5/10) ≈ 1.0x (neutral)
        # - High trust (8–10) gives a modest discount (~0.90–0.95x)
        # - Low trust (0–3) increases score more aggressively (up to ~1.30x)
        if trust_score is not None:
            try:
                t = float(trust_score)
            except (TypeError, ValueError):
                t = 0.0
            # Clamp input to expected TrustEngine range
            t = max(0.0, min(10.0, t))

            # Discrete Mapping §10 Step 5:
            # 9-10→0.7x, 7-8→0.85x, 5-6→1.0x, 3-4→1.2x, 1-2→1.5x, 0→1.1x
            if t >= 9.0:
                trust_multiplier = 0.7
            elif t >= 7.0:
                trust_multiplier = 0.85
            elif t >= 5.0:
                trust_multiplier = 1.0
            elif t >= 3.0:
                trust_multiplier = 1.2
            elif t >= 1.0:
                trust_multiplier = 1.5
            else:
                # 0-0.9 range
                trust_multiplier = 1.1

            pre_trust_score = score
            score *= trust_multiplier
            trust_delta = score - pre_trust_score

            # Choose color based on whether trust lowered or raised risk.
            if trust_delta < 0:
                color = "green"
            elif t <= 3.0:
                color = "red"
            else:
                color = "yellow"

            verb = "subtracted" if trust_delta < 0 else "added"
            breakdown.append(
                f"  [{color}]🧩 Trust Score [/]{t:.1f}/10 → x{trust_multiplier:.2f} "
                f"({verb} [bold]{abs(trust_delta):.1f}[/bold] pts)"
            )

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

        # ── Step 7: AI Adjustment (max ±15 per Checkpoint 1a) ─────────────────
        ai_adj = max(-15.0, min(15.0, float(ai_pri_delta)))
        if ai_adj != 0.0:
            score += ai_adj
            breakdown.append(
                f"  [magenta]🤖 AI Triage Adjustment[/magenta] → [bold]{ai_adj:+.1f}[/bold] pts"
            )

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
