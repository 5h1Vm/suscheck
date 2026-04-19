"""Suppression governance helpers.

This layer does not silently hide findings. It only surfaces governance
state and auto-flags expired suppressions as review findings.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any

from suscheck.core.finding import Finding, FindingType, Severity


@dataclass(frozen=True)
class SuppressionEntry:
    owner: str
    reason: str
    expiry: str
    scope: dict[str, Any]


@dataclass(frozen=True)
class SuppressionGovernanceResult:
    findings: list[Finding]
    trace: list[str]
    loaded_entries: int


_DEFAULT_SUPPRESSION_FILE = Path.cwd() / ".suscheck" / "suppressions.json"


def _parse_expiry(raw_expiry: str) -> date | None:
    try:
        return datetime.strptime(raw_expiry, "%Y-%m-%d").date()
    except ValueError:
        return None


def _scope_matches(scope: dict[str, Any], finding: Finding) -> bool:
    finding_id = str(scope.get("finding_id") or "").strip()
    module = str(scope.get("module") or "").strip()
    path_contains = str(scope.get("file_path_contains") or "").strip()

    if finding_id and finding_id not in {"*", finding.finding_id}:
        return False
    if module and module not in {"*", finding.module}:
        return False
    if path_contains and path_contains not in (finding.file_path or ""):
        return False
    return True


def load_suppressions(path: str | Path | None = None) -> list[SuppressionEntry]:
    source = Path(path) if path else _DEFAULT_SUPPRESSION_FILE
    if not source.is_file():
        return []

    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []

    entries: list[SuppressionEntry] = []
    if not isinstance(raw, list):
        return entries

    for item in raw:
        if not isinstance(item, dict):
            continue
        owner = str(item.get("owner") or "").strip()
        reason = str(item.get("reason") or "").strip()
        expiry = str(item.get("expiry") or "").strip()
        scope = item.get("scope") if isinstance(item.get("scope"), dict) else {}
        if not owner or not reason or not expiry:
            continue
        entries.append(SuppressionEntry(owner=owner, reason=reason, expiry=expiry, scope=scope))
    return entries


def evaluate_suppressions(
    findings: list[Finding],
    suppressions: list[SuppressionEntry],
    *,
    today: date | None = None,
) -> SuppressionGovernanceResult:
    """Flag expired suppressions and emit trace notes for active matches."""
    current_day = today or date.today()
    governance_findings: list[Finding] = []
    trace: list[str] = []

    for suppression in suppressions:
        expiry_day = _parse_expiry(suppression.expiry)
        if expiry_day is None:
            trace.append(f"suppression: invalid expiry for {suppression.owner} ({suppression.expiry})")
            continue

        matched = [finding for finding in findings if _scope_matches(suppression.scope, finding)]
        if expiry_day < current_day:
            trace.append(
                f"suppression: expired scope for {suppression.owner} on {suppression.expiry}"
            )
            governance_findings.append(
                Finding(
                    module="governance",
                    finding_id=f"SUPPRESSION-EXPIRED-{suppression.owner}"[:72],
                    title="Expired suppression entry detected",
                    description=(
                        "A suppression entry has passed its expiry date and must be reviewed. "
                        "Expired suppressions are auto-flagged instead of being applied silently."
                    ),
                    severity=Severity.MEDIUM,
                    finding_type=FindingType.REVIEW_NEEDED,
                    confidence=0.95,
                    evidence={
                        "owner": suppression.owner,
                        "reason": suppression.reason,
                        "expiry": suppression.expiry,
                        "scope": suppression.scope,
                    },
                    needs_human_review=True,
                    review_reason="Suppression expired",
                )
            )
            continue

        if matched:
            trace.append(
                f"suppression: active scope for {suppression.owner} matched {len(matched)} finding(s)"
            )

    return SuppressionGovernanceResult(
        findings=governance_findings,
        trace=trace,
        loaded_entries=len(suppressions),
    )
