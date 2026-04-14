from __future__ import annotations

from pathlib import Path

from suscheck.modules.supply_chain.auditor import SupplyChainAuditor


def test_scan_source_imports_rejects_malformed_npm_candidates(monkeypatch, tmp_path: Path) -> None:
    sample = tmp_path / "sample.js"
    sample.write_text(
        "const a = require('base64; exec(base64)');\n"
        "const b = require('lodash/map');\n"
        "import scoped from '@scope/pkg/subpath';\n"
        "import leftPad from 'left-pad';\n",
        encoding="utf-8",
    )

    called_targets: list[str] = []

    class _TrustResult:
        findings = []

    class _TrustEngine:
        def scan(self, target: str):
            called_targets.append(target)
            return _TrustResult()

    monkeypatch.setattr("suscheck.modules.supply_chain.auditor.TrustEngine", _TrustEngine)

    auditor = SupplyChainAuditor()
    findings = auditor.scan_source_imports(str(sample))

    assert findings == []
    assert "npm:lodash" in called_targets
    assert "npm:@scope/pkg" in called_targets
    assert "npm:left-pad" in called_targets
    assert all("base64; exec(base64)" not in target for target in called_targets)


def test_scan_source_imports_skips_all_invalid_candidates(monkeypatch, tmp_path: Path) -> None:
    sample = tmp_path / "invalid.js"
    sample.write_text("const x = require('base64; exec(base64)');\n", encoding="utf-8")

    called_targets: list[str] = []

    class _TrustResult:
        findings = []

    class _TrustEngine:
        def scan(self, target: str):
            called_targets.append(target)
            return _TrustResult()

    monkeypatch.setattr("suscheck.modules.supply_chain.auditor.TrustEngine", _TrustEngine)

    auditor = SupplyChainAuditor()
    findings = auditor.scan_source_imports(str(sample))

    assert findings == []
    assert called_targets == []
