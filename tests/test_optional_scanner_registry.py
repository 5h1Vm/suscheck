from __future__ import annotations

from suscheck.modules.optional.registry import OptionalScannerRegistry


def test_optional_scanner_registry_defaults_disabled(monkeypatch) -> None:
    monkeypatch.delenv("SUSCHECK_ENABLE_OPENVAS", raising=False)
    monkeypatch.delenv("SUSCHECK_ENABLE_ZAP", raising=False)
    monkeypatch.delenv("SUSCHECK_ENABLE_NUCLEI", raising=False)
    monkeypatch.delenv("SUSCHECK_ENABLE_TRIVY", raising=False)
    monkeypatch.delenv("SUSCHECK_ENABLE_GRYPE", raising=False)

    registry = OptionalScannerRegistry()
    adapters = registry.list_adapters()

    assert len(adapters) >= 5
    assert all(adapter.enabled is False for adapter in adapters)


def test_optional_scanner_registry_respects_env_toggles(monkeypatch) -> None:
    monkeypatch.setenv("SUSCHECK_ENABLE_NUCLEI", "true")
    monkeypatch.setenv("SUSCHECK_ENABLE_ZAP", "1")

    registry = OptionalScannerRegistry()
    enabled_names = {adapter.name for adapter in registry.list_enabled()}

    assert "nuclei" in enabled_names
    assert "zap" in enabled_names
