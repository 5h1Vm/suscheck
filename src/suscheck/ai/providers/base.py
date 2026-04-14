"""Abstract AI provider for triage (Increment 13)."""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import Any


class AIProvider(ABC):
    """Pluggable LLM backend; all methods use only explicit config (no fake responses)."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider id (e.g. openai, ollama)."""
        ...

    def is_configured(self) -> bool:
        """Return True if this provider can attempt a live API call."""
        return False

    async def verify_connectivity(self) -> bool:
        """Best-effort provider health probe.

        Providers may override this, but the default implementation performs a minimal
        triage call in a background thread so diagnostics and health checks can share
        a common contract without requiring every backend to implement a separate ping.
        """
        if not self.is_configured():
            return False

        try:
            await asyncio.to_thread(
                self.complete_triage_json,
                system_prompt='{"healthcheck": true}',
                user_prompt='{"scan_target":"healthcheck","artifact_type":"diagnostic","findings":[]}',
                timeout_sec=30,
            )
            return True
        except Exception:
            return False

    @abstractmethod
    def complete_triage_json(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        timeout_sec: int = 90,
    ) -> dict[str, Any]:
        """Call the model and return a parsed JSON object (not a string).

        Raises on transport/HTTP errors or invalid JSON payload.
        """
        ...

    @abstractmethod
    def complete_narrative(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        timeout_sec: int = 120,
    ) -> str:
        """Call the model and return a narrative string (Markdown)."""
        ...
