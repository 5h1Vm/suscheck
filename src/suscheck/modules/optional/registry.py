"""Registry for optional external scanner adapters.

These adapters are disabled-by-default and intended for post-beta expansion
(OpenVAS/Greenbone, ZAP, Nuclei, Trivy/Grype, etc.).
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class OptionalScannerAdapter:
    name: str
    env_toggle: str
    description: str
    enabled: bool


class OptionalScannerRegistry:
    """Resolve optional scanner adapter availability from environment toggles."""

    _DEFINITIONS: list[tuple[str, str, str]] = [
        ("openvas", "SUSCHECK_ENABLE_OPENVAS", "OpenVAS/Greenbone network vulnerability scanner"),
        ("zap", "SUSCHECK_ENABLE_ZAP", "OWASP ZAP web application scanner"),
        ("nuclei", "SUSCHECK_ENABLE_NUCLEI", "Nuclei template-driven scanner"),
        ("trivy", "SUSCHECK_ENABLE_TRIVY", "Trivy container/filesystem vulnerability scanner"),
        ("grype", "SUSCHECK_ENABLE_GRYPE", "Grype SBOM/image vulnerability scanner"),
    ]

    @staticmethod
    def _is_enabled(env_name: str) -> bool:
        value = os.environ.get(env_name, "").strip().lower()
        return value in {"1", "true", "yes", "on"}

    def list_adapters(self) -> list[OptionalScannerAdapter]:
        return [
            OptionalScannerAdapter(
                name=name,
                env_toggle=env_toggle,
                description=description,
                enabled=self._is_enabled(env_toggle),
            )
            for name, env_toggle, description in self._DEFINITIONS
        ]

    def list_enabled(self) -> list[OptionalScannerAdapter]:
        return [adapter for adapter in self.list_adapters() if adapter.enabled]
