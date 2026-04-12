"""No-op AI provider."""

from __future__ import annotations

from typing import Any

from suscheck.ai.providers.base import AIProvider


class NoneProvider(AIProvider):
    @property
    def name(self) -> str:
        return "none"

    def is_configured(self) -> bool:
        return False

    def complete_triage_json(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        timeout_sec: int = 90,
    ) -> dict[str, Any]:
        raise RuntimeError("NoneProvider cannot complete triage")

    def complete_narrative(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        timeout_sec: int = 120,
    ) -> str:
        raise RuntimeError("NoneProvider cannot complete narrative")
