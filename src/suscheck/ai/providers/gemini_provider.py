"""Google Gemini (Generative Language API) — JSON response mode."""

from __future__ import annotations

import logging
from typing import Any

from suscheck.ai.http_retry import post_json_with_retry
from suscheck.ai.json_extract import parse_json_response
from suscheck.ai.providers.base import AIProvider

logger = logging.getLogger(__name__)


class GeminiProvider(AIProvider):
    """Uses ``v1beta`` generateContent with ``responseMimeType: application/json``."""

    def __init__(self, *, api_key: str, model: str) -> None:
        self._api_key = (api_key or "").strip()
        self._model = (model or "").strip()

    @property
    def name(self) -> str:
        return "gemini"

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
            raise RuntimeError("Gemini missing API key or model")

        url = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self._model}:generateContent"
        )
        body: dict[str, Any] = {
            "systemInstruction": {"parts": [{"text": system_prompt}]},
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": user_prompt}],
                }
            ],
            "generationConfig": {
                "temperature": 0.2,
                "responseMimeType": "application/json",
            },
        }
        r = post_json_with_retry(
            url,
            headers={"Content-Type": "application/json"},
            json_body=body,
            timeout_sec=float(timeout_sec),
            params={"key": self._api_key},
        )
        if not r.ok:
            logger.warning("Gemini HTTP %s: %s", r.status_code, r.text[:500])
            r.raise_for_status()
        data = r.json()
        try:
            parts = data["candidates"][0]["content"]["parts"]
            text = parts[0].get("text", "")
        except (KeyError, IndexError, TypeError) as e:
            raise ValueError(f"Unexpected Gemini response: {data!r}") from e
        if not text.strip():
            raise ValueError(f"Empty Gemini content: {data!r}")
        return parse_json_response(text)
