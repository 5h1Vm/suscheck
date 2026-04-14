from __future__ import annotations

from types import SimpleNamespace

from rich.console import Console

from suscheck.core.finding import Finding, FindingType, Severity
from suscheck.services.analysis_service import (
	execute_ai_triage_phase,
	execute_explain_indicator_phase,
	execute_package_trust_phase,
)


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


def test_execute_explain_indicator_phase_collects_findings(monkeypatch) -> None:
	def _finding(module: str, fid: str) -> Finding:
		return Finding(
			module=module,
			finding_id=fid,
			title="finding",
			description="desc",
			severity=Severity.LOW,
			finding_type=FindingType.SUSPICIOUS_BEHAVIOR,
			confidence=0.9,
		)

	class _Tier0:
		def check_file(self, _file):
			return SimpleNamespace(findings=[_finding("tier0", "T0-1")])

	class _CodeScanner:
		def scan_file(self, _file):
			return SimpleNamespace(findings=[_finding("code", "C-1")])

	class _Semgrep:
		is_installed = True

		def scan_file(self, _file):
			return SimpleNamespace(findings=[_finding("semgrep", "S-1")])

	monkeypatch.setattr("suscheck.modules.external.engine.Tier0Engine", _Tier0)
	monkeypatch.setattr("suscheck.modules.code.scanner.CodeScanner", _CodeScanner)
	monkeypatch.setattr("suscheck.modules.semgrep_runner.SemgrepRunner", _Semgrep)
	monkeypatch.setattr("suscheck.services.analysis_service.render_findings", lambda _findings: None)

	detection = SimpleNamespace(
		type_mismatch=True,
		mismatch_detail=".txt has script content",
		artifact_type=SimpleNamespace(value="code"),
		is_polyglot=True,
	)

	findings = execute_explain_indicator_phase(
		file="demo.txt",
		detection=detection,
		console=Console(record=True),
	)

	finding_ids = {f.finding_id for f in findings}
	assert "DETECT-MISMATCH" in finding_ids
	assert "DETECT-POLYGLOT" in finding_ids
	assert "T0-1" in finding_ids
	assert "C-1" in finding_ids
	assert "S-1" in finding_ids
