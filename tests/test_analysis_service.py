from __future__ import annotations

from types import SimpleNamespace

from rich.console import Console

from suscheck.core.finding import Finding, FindingType, Severity
from suscheck.services.analysis_service import execute_ai_triage_phase, execute_package_trust_phase


def test_execute_package_trust_phase_for_package_target(monkeypatch) -> None:
	finding = Finding(
		module="trust_engine",
		finding_id="TRUST-1",
		title="trust finding",
		description="desc",
		severity=Severity.LOW,
		finding_type=FindingType.REVIEW_NEEDED,
		confidence=0.9,
	)

	class _Engine:
		def scan(self, _target):
			return SimpleNamespace(error=None, trust_score=8.5, findings=[finding])

	monkeypatch.setattr("suscheck.modules.supply_chain.trust_engine.TrustEngine", _Engine)

	trust_score, findings, modules = execute_package_trust_phase(
		target="requests",
		artifact_type="package",
		modules_ran=["tier0"],
		console=Console(record=True),
	)

	assert trust_score == 8.5
	assert findings == [finding]
	assert "supply_chain" in modules


def test_execute_package_trust_phase_non_package_target() -> None:
	trust_score, findings, modules = execute_package_trust_phase(
		target="/tmp/demo.py",
		artifact_type="code",
		modules_ran=["tier0"],
		console=Console(record=True),
	)

	assert trust_score is None
	assert findings == []
	assert modules == ["tier0"]


def test_execute_ai_triage_phase_updates_modules(monkeypatch) -> None:
	finding = Finding(
		module="code",
		finding_id="F-1",
		title="finding",
		description="desc",
		severity=Severity.HIGH,
		finding_type=FindingType.SUSPICIOUS_BEHAVIOR,
		confidence=0.9,
	)

	class _Triage:
		def __init__(self):
			self.pri_adjustment = 5.0
			self.ran = True

	def _fake_run_ai_triage(*_args, **_kwargs):
		finding.ai_explanation = "triaged"
		return _Triage()

	monkeypatch.setattr("suscheck.ai.triage_engine.run_ai_triage", _fake_run_ai_triage)

	delta, modules = execute_ai_triage_phase(
		no_ai=False,
		findings=[finding],
		target="sample.py",
		artifact_type="code",
		modules_ran=["tier0", "code"],
		console=Console(record=True),
	)

	assert delta == 5.0
	assert "ai_triage" in modules


def test_execute_ai_triage_phase_skips_when_disabled() -> None:
	delta, modules = execute_ai_triage_phase(
		no_ai=True,
		findings=[],
		target="sample.py",
		artifact_type="code",
		modules_ran=["tier0", "code"],
		console=Console(record=True),
	)

	assert delta == 0.0
	assert modules == ["tier0", "code"]
