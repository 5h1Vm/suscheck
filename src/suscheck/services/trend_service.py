"""Historical trend helpers for repeated scans of the same target."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from suscheck.core.finding import ScanSummary


@dataclass(frozen=True)
class TrendSnapshot:
    target: str
    artifact_type: str
    pri_score: int
    verdict: str
    total_findings: int
    coverage_complete: bool


@dataclass(frozen=True)
class TrendResult:
    trace: list[str]
    previous_snapshot: TrendSnapshot | None
    current_snapshot: TrendSnapshot


def _trend_store_path() -> Path:
    override = os.environ.get("SUSCHECK_TREND_FILE")
    if override:
        return Path(override)
    return Path.cwd() / ".suscheck" / "history" / "scan_trends.json"


def _load_store(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return raw if isinstance(raw, dict) else {}


def _save_store(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def _snapshot_key(summary: ScanSummary) -> str:
    return f"{summary.artifact_type}:{summary.target}"


def _make_snapshot(summary: ScanSummary) -> TrendSnapshot:
    return TrendSnapshot(
        target=summary.target,
        artifact_type=summary.artifact_type,
        pri_score=summary.pri_score,
        verdict=summary.verdict.value,
        total_findings=summary.total_findings,
        coverage_complete=summary.coverage_complete,
    )


def compare_and_record_trend(summary: ScanSummary, *, store_path: str | Path | None = None) -> TrendResult:
    """Compare the current scan to the previous run for the same target and record the new snapshot."""
    path = Path(store_path) if store_path else _trend_store_path()
    store = _load_store(path)
    key = _snapshot_key(summary)
    current_snapshot = _make_snapshot(summary)
    previous_raw = store.get(key)
    previous_snapshot = None

    if isinstance(previous_raw, dict):
        try:
            previous_snapshot = TrendSnapshot(
                target=str(previous_raw["target"]),
                artifact_type=str(previous_raw["artifact_type"]),
                pri_score=int(previous_raw["pri_score"]),
                verdict=str(previous_raw["verdict"]),
                total_findings=int(previous_raw["total_findings"]),
                coverage_complete=bool(previous_raw["coverage_complete"]),
            )
        except (KeyError, TypeError, ValueError):
            previous_snapshot = None

    trace: list[str] = []
    if previous_snapshot is None:
        trace.append("trend: no previous scan snapshot for this target")
    else:
        delta_pri = current_snapshot.pri_score - previous_snapshot.pri_score
        delta_findings = current_snapshot.total_findings - previous_snapshot.total_findings
        delta_coverage = "unchanged"
        if previous_snapshot.coverage_complete != current_snapshot.coverage_complete:
            delta_coverage = (
                "improved" if current_snapshot.coverage_complete else "degraded"
            )
        trace.append(
            f"trend: previous PRI {previous_snapshot.pri_score}/100 -> {current_snapshot.pri_score}/100 ({delta_pri:+d})"
        )
        trace.append(
            f"trend: previous findings {previous_snapshot.total_findings} -> {current_snapshot.total_findings} ({delta_findings:+d})"
        )
        trace.append(
            f"trend: coverage {delta_coverage}; previous={previous_snapshot.coverage_complete}, current={current_snapshot.coverage_complete}"
        )

    store[key] = asdict(current_snapshot)
    _save_store(path, store)

    return TrendResult(trace=trace, previous_snapshot=previous_snapshot, current_snapshot=current_snapshot)
