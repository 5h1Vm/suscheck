"""Finding normalization utilities used before PRI scoring.

This pass keeps risk logic intact while making inputs deterministic:
1) Deduplicate repeated findings from the same module/location/evidence tuple.
2) Correlate shared indicators seen across multiple modules.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from suscheck.core.finding import Finding


_CORRELATION_EVIDENCE_KEYS = (
    "value",
    "url",
    "ip",
    "ipv4",
    "domain",
    "sha256",
    "sha1",
    "md5",
    "ioc",
)


@dataclass
class CorrelatedIndicator:
    key: str
    modules: list[str] = field(default_factory=list)
    finding_ids: list[str] = field(default_factory=list)


@dataclass
class NormalizedFindings:
    findings: list[Finding]
    deduplicated_count: int = 0
    correlated_indicators: list[CorrelatedIndicator] = field(default_factory=list)


def _compact_evidence(evidence: dict) -> str:
    try:
        return json.dumps(evidence or {}, sort_keys=True, separators=(",", ":"), default=str)
    except Exception:
        return str(evidence)


def _dedupe_signature(finding: Finding) -> tuple[str, str, str, int | None, str, str]:
    return (
        finding.module,
        finding.finding_type.value,
        finding.file_path or "",
        finding.line_number,
        finding.context or "main",
        _compact_evidence(finding.evidence or {}),
    )


def _indicator_key(finding: Finding) -> str | None:
    evidence = finding.evidence or {}
    for key in _CORRELATION_EVIDENCE_KEYS:
        value = evidence.get(key)
        if value:
            return f"indicator:{str(value).strip().lower()}"
    return None


def normalize_findings(findings: list[Finding]) -> NormalizedFindings:
    seen: set[tuple[str, str, str, int | None, str, str]] = set()
    deduped: list[Finding] = []

    for finding in findings:
        sig = _dedupe_signature(finding)
        if sig in seen:
            continue
        seen.add(sig)
        deduped.append(finding)

    indicator_modules: dict[str, set[str]] = {}
    indicator_findings: dict[str, list[str]] = {}

    for finding in deduped:
        key = _indicator_key(finding)
        if not key:
            continue
        indicator_modules.setdefault(key, set()).add(finding.module)
        indicator_findings.setdefault(key, []).append(finding.finding_id)

    correlated: list[CorrelatedIndicator] = []
    for key, modules in indicator_modules.items():
        if len(modules) < 2:
            continue
        correlated.append(
            CorrelatedIndicator(
                key=key,
                modules=sorted(modules),
                finding_ids=sorted(set(indicator_findings.get(key, []))),
            )
        )

    return NormalizedFindings(
        findings=deduped,
        deduplicated_count=max(0, len(findings) - len(deduped)),
        correlated_indicators=correlated,
    )
