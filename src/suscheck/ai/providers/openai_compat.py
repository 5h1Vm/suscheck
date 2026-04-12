"""OpenAI-compatible Chat Completions (OpenAI, Groq, OpenRouter, Mistral, Cerebras, SambaNova, …)."""

from __future__ import annotations

import logging
import os
from typing import Any

from suscheck.ai.http_retry import post_json_with_retry
from suscheck.ai.json_extract import parse_json_response
from suscheck.ai.providers.base import AIProvider

logger = logging.getLogger(__name__)


class OpenAICompatProvider(AIProvider):
    def __init__(
        self,
        *,
        name: str,
        api_key: str,
        model: str,
        base_url: str,
    ) -> None:
        self._id = name
        self._api_key = (api_key or "").strip()
        self._model = (model or "").strip()
        self._base = base_url.rstrip("/")

    @property
    def name(self) -> str:
        return self._id

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
            raise RuntimeError("OpenAI-compatible provider missing API key or model")

        url = f"{self._base}/chat/completions"
        headers: dict[str, str] = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        if self._id == "openrouter":
            ref = os.environ.get("OPENROUTER_HTTP_REFERER", "").strip()
            if ref:
                headers["HTTP-Referer"] = ref
            headers["X-Title"] = (
                os.environ.get("OPENROUTER_APP_TITLE", "SusCheck").strip() or "SusCheck"
            )

        body: dict[str, Any] = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
        }
        json_mode = os.environ.get("SUSCHECK_AI_JSON_MODE", "1").strip().lower() not in (
            "0",
            "false",
            "no",
            "off",
        )
        if json_mode:
            body["response_format"] = {"type": "json_object"}

        r = post_json_with_retry(
            url,
            headers=headers,
            json_body=body,
            timeout_sec=float(timeout_sec),
        )
        if not r.ok and json_mode and r.status_code == 400:
            body2 = {k: v for k, v in body.items() if k != "response_format"}
            logger.info("Retrying chat completions without response_format (400 from provider)")
            r = post_json_with_retry(
                url,
                headers=headers,
                json_body=body2,
                timeout_sec=float(timeout_sec),
            )
        if not r.ok:
            logger.warning("AI HTTP %s: %s", r.status_code, r.text[:500])
            r.raise_for_status()
        data = r.json()
        return parse_json_response(text)

    def complete_narrative(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        timeout_sec: int = 120,
    ) -> str:
        if not self.is_configured():
            raise RuntimeError("OpenAI-compatible provider missing API key or model")

        url = f"{self._base}/chat/completions"
        headers: dict[str, str] = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        if self._id == "openrouter":
            ref = os.environ.get("OPENROUTER_HTTP_REFERER", "").strip()
            if ref:
                headers["HTTP-Referer"] = ref
            headers["X-Title"] = os.environ.get("OPENROUTER_APP_TITLE", "SusCheck").strip() or "SusCheck"

        body: dict[str, Any] = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.4,
        }
        r = post_json_with_retry(
            url,
            headers=headers,
            json_body=body,
            timeout_sec=float(timeout_sec),
        )
        if not r.ok:
            r.raise_for_status()
        
        data = r.json()
        try:
            return data["choices"][0]["message"]["content"].strip()
        except (KeyError, IndexError, TypeError) as e:
            raise ValueError(f"Unexpected chat completions shape: {data!r}") from e


def default_base_for_provider(provider_id: str) -> str:
    """Resolve API base; ``SUSCHECK_AI_BASE_URL`` overrides everything when set."""
    env_url = os.environ.get("SUSCHECK_AI_BASE_URL", "").strip()
    if env_url:
        return env_url.rstrip("/")
    p = provider_id.lower()
    return {
        "groq": "https://api.groq.com/openai/v1",
        "openrouter": "https://openrouter.ai/api/v1",
        "mistral": "https://api.mistral.ai/v1",
        "cerebras": "https://api.cerebras.ai/v1",
        "sambanova": "https://api.sambanova.ai/v1",
        "openai": "https://api.openai.com/v1",
    }.get(p, "https://api.openai.com/v1")
