"""AI triage over scan findings — explanations, FP hints, PRI delta (Increment 13)."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

from suscheck.ai.factory import create_ai_provider
from suscheck.core.finding import Finding, Severity

logger = logging.getLogger(__name__)

MAX_FINDINGS_FOR_TRIAGE = 24

SYSTEM_PROMPT = """You assist a pre-execution security scanner (SusCheck). You receive JSON describing \
security findings from static analysis. Respond with ONLY valid JSON (no markdown), exactly matching this schema:
{
  "pri_adjustment": <number from -15 to 15>,
  "findings": [
    {
      "finding_id": "<string, must match input>",
      "explanation": "<1-3 sentences, plain English>",
      "likely_false_positive": <boolean>,
      "confidence": <number 0.0-1.0>
    }
  ]
}
Rules:
- pri_adjustment: small calibration to the overall risk score; negative if many findings look benign (tests, docs, placeholders), positive if they reinforce real threat.
- likely_false_positive: true only with strong justification (e.g. obvious test fixture, commented example).
- Include only findings you analyzed; finding_id must match the input exactly.
"""


@dataclass
class TriageRunResult:
    pri_adjustment: float
    ran: bool
    provider_name: str
    error: str | None = None


def _severity_rank(s: Severity) -> int:
    order = (
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    )
    try:
        return order.index(s)
    except ValueError:
        return 99


def _brief_findings(findings: list[Finding]) -> list[dict[str, Any]]:
    sorted_f = sorted(findings, key=lambda f: (_severity_rank(f.severity), f.finding_id))
    out = []
    for f in sorted_f[:MAX_FINDINGS_FOR_TRIAGE]:
        out.append(
            {
                "finding_id": f.finding_id,
                "module": f.module,
                "title": f.title,
                "severity": f.severity.value,
                "type": f.finding_type.value,
                "confidence": f.confidence,
                "line_number": f.line_number,
                "code_snippet": (f.code_snippet or "")[:500],
                "description": (f.description or "")[:600],
            }
        )
    return out


def apply_triage_response(findings: list[Finding], data: dict[str, Any]) -> float:
    """Mutate findings with AI fields; return clamped pri_adjustment."""
    raw_adj = data.get("pri_adjustment", 0)
    try:
        pri_adj = float(raw_adj)
    except (TypeError, ValueError):
        pri_adj = 0.0
    pri_adj = max(-15.0, min(15.0, pri_adj))

    by_id = {f.finding_id: f for f in findings}
    items = data.get("findings")
    if not isinstance(items, list):
        return pri_adj

    for item in items:
        if not isinstance(item, dict):
            continue
        fid = item.get("finding_id")
        if not fid or fid not in by_id:
            continue
        f = by_id[fid]
        exp = item.get("explanation")
        if isinstance(exp, str) and exp.strip():
            f.ai_explanation = exp.strip()[:4000]
        lfp = item.get("likely_false_positive")
        if isinstance(lfp, bool):
            f.ai_false_positive = lfp
        conf = item.get("confidence")
        if conf is not None:
            try:
                c = float(conf)
                if 0.0 <= c <= 1.0:
                    f.ai_confidence = c
            except (TypeError, ValueError):
                pass

    return pri_adj


def run_ai_triage(
    findings: list[Finding],
    *,
    target: str,
    artifact_type: str,
    console: Any = None,
) -> TriageRunResult:
    """If configured, call LLM once; update findings in place."""
    provider = create_ai_provider()
    if not provider.is_configured():
        return TriageRunResult(0.0, False, provider.name, None)

    if not findings:
        return TriageRunResult(0.0, False, provider.name, None)

    brief = _brief_findings(findings)
    user_payload = {
        "scan_target": target,
        "artifact_type": artifact_type,
        "findings": brief,
    }
    user_prompt = json.dumps(user_payload, indent=2)

    try:
        if console:
            console.print(f"  [dim]AI triage ({provider.name}) analyzing {len(brief)} finding(s)...[/dim]")
        data = provider.complete_triage_json(
            system_prompt=SYSTEM_PROMPT,
            user_prompt=user_prompt,
            timeout_sec=120,
        )
        pri_adj = apply_triage_response(findings, data)
        return TriageRunResult(pri_adj, True, provider.name, None)
    except Exception as e:
        logger.exception("AI triage failed")
        err = str(e)[:500]
        if console:
            console.print(f"  [yellow]AI triage failed: {err}[/yellow]")
        return TriageRunResult(0.0, False, provider.name, err)
