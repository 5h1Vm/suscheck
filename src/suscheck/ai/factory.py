"""Instantiate AI provider from environment."""

from __future__ import annotations

import logging
import os

from suscheck.ai.key_resolution import api_key_for_provider
from suscheck.ai.providers.anthropic_provider import AnthropicProvider
from suscheck.ai.providers.base import AIProvider
from suscheck.ai.providers.gemini_provider import GeminiProvider
from suscheck.ai.providers.none_provider import NoneProvider
from suscheck.ai.providers.ollama_provider import OllamaProvider, ollama_host
from suscheck.ai.providers.openai_compat import OpenAICompatProvider, default_base_for_provider

logger = logging.getLogger(__name__)

# OpenAI-compatible provider ids (shared HTTP client + base URL table)
_OPENAI_COMPAT_IDS = frozenset(
    {
        "openai",
        "groq",
        "openrouter",
        "mistral",
        "cerebras",
        "sambanova",
    }
)


def create_ai_provider(name: str | None = None) -> AIProvider:
    """Build provider from name or env. Never returns None."""
    pid = (name or os.environ.get("SUSCHECK_AI_PROVIDER", "none")).strip().lower()
    model = os.environ.get("SUSCHECK_AI_MODEL", "").strip()

    if pid in ("none", "", "off"):
        return NoneProvider()

    if pid == "ollama":
        return OllamaProvider(model=model, host=ollama_host())

    key = api_key_for_provider(pid)

    if pid == "anthropic":
        return AnthropicProvider(api_key=key, model=model)

    if pid in ("google", "gemini"):
        return GeminiProvider(api_key=key, model=model)

    if pid in _OPENAI_COMPAT_IDS:
        base = default_base_for_provider(pid)
        return OpenAICompatProvider(name=pid, api_key=key, model=model, base_url=base)

    if name: # If specifically requested but not matched
         return NoneProvider()

    logger.warning("Unknown SUSCHECK_AI_PROVIDER=%r — AI triage disabled.", pid)
    return NoneProvider()

def get_available_providers() -> list[str]:
    """Return list of provider IDs that have configured API keys."""
    available = []
    # 1. Check direct suspects
    for pid in ["anthropic", "gemini", "google", "ollama"]:
        p = create_ai_provider(pid)
        if p.is_configured():
            available.append(pid)
    # 2. Check OpenAI-compat group
    for pid in _OPENAI_COMPAT_IDS:
        p = create_ai_provider(pid)
        if p.is_configured():
            available.append(pid)
    return available
