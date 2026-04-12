"""Ollama local /api/chat."""

from __future__ import annotations

import logging
import os
from typing import Any

from suscheck.ai.http_retry import post_json_with_retry
from suscheck.ai.json_extract import parse_json_response
from suscheck.ai.providers.base import AIProvider

logger = logging.getLogger(__name__)


class OllamaProvider(AIProvider):
    def __init__(self, *, model: str, host: str) -> None:
        self._model = (model or "").strip()
        self._host = (host or "http://localhost:11434").rstrip("/")

    @property
    def name(self) -> str:
        return "ollama"

    def is_configured(self) -> bool:
        return bool(self._model)

    def complete_triage_json(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        timeout_sec: int = 90,
    ) -> dict[str, Any]:
        if not self._model:
            raise RuntimeError("Ollama model not set (SUSCHECK_AI_MODEL)")

        url = f"{self._host}/api/chat"
        body = {
            "model": self._model,
            "stream": False,
            "format": "json",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        r = post_json_with_retry(
            url,
            headers={"Content-Type": "application/json"},
            json_body=body,
            timeout_sec=float(timeout_sec),
        )
        if not r.ok:
            logger.warning("Ollama HTTP %s: %s", r.status_code, r.text[:500])
            r.raise_for_status()
        data = r.json()
        text = data.get("message", {}).get("content", "")
        if not text:
            raise ValueError(f"Unexpected Ollama response: {data!r}")
        return parse_json_response(text)


def ollama_host() -> str:
    return os.environ.get("SUSCHECK_OLLAMA_HOST", "http://localhost:11434").strip()
