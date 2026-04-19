from __future__ import annotations

from suscheck.services.summary_service import build_optional_scanner_trace


def test_build_optional_scanner_trace_defaults_to_none(monkeypatch) -> None:
    monkeypatch.delenv("SUSCHECK_ENABLE_OPENVAS", raising=False)
    monkeypatch.delenv("SUSCHECK_ENABLE_ZAP", raising=False)
    monkeypatch.delenv("SUSCHECK_ENABLE_NUCLEI", raising=False)
    monkeypatch.delenv("SUSCHECK_ENABLE_TRIVY", raising=False)
    monkeypatch.delenv("SUSCHECK_ENABLE_GRYPE", raising=False)

    trace = build_optional_scanner_trace()

    assert trace == ["optional-scanners: enabled=none (all disabled-by-default)"]


def test_build_optional_scanner_trace_with_enabled_adapters(monkeypatch) -> None:
    monkeypatch.setenv("SUSCHECK_ENABLE_ZAP", "1")
    monkeypatch.setenv("SUSCHECK_ENABLE_NUCLEI", "true")

    trace = build_optional_scanner_trace()

    assert trace == ["optional-scanners: enabled=nuclei,zap"]
