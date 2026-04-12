"""Anthropic Messages API via HTTP (no anthropic SDK required)."""

from __future__ import annotations

import logging
from typing import Any

from suscheck.ai.http_retry import post_json_with_retry
from suscheck.ai.json_extract import parse_json_response
from suscheck.ai.providers.base import AIProvider

logger = logging.getLogger(__name__)

ANTHROPIC_VERSION = "2023-06-01"


class AnthropicProvider(AIProvider):
    def __init__(self, *, api_key: str, model: str) -> None:
        self._api_key = (api_key or "").strip()
        self._model = (model or "").strip()

    @property
    def name(self) -> str:
        return "anthropic"

    def is_configured(self) -> bool:
        return bool(self._api_key and self._model)

    def complete_triage_json(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        timeout_sec: int = 90,
    ) -> dict[str, Any]:
        if not self.is_configured():
            raise RuntimeError("Anthropic missing API key or model")

        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": ANTHROPIC_VERSION,
            "Content-Type": "application/json",
        }
        body = {
            "model": self._model,
            "max_tokens": 4096,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
        }
        r = post_json_with_retry(
            url,
            headers=headers,
            json_body=body,
            timeout_sec=float(timeout_sec),
        )
        if not r.ok:
            logger.warning("Anthropic HTTP %s: %s", r.status_code, r.text[:500])
            r.raise_for_status()
        data = r.json()
        blocks = data.get("content") or []
        text = ""
        for b in blocks:
            if isinstance(b, dict) and b.get("type") == "text":
                text += b.get("text", "")
        if not text.strip():
            raise ValueError(f"Unexpected Anthropic response: {data!r}")
        return parse_json_response(text)
