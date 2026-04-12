"""Resolve API keys: prefer ``SUSCHECK_AI_KEY``, then common provider-specific env names."""

from __future__ import annotations

import os


def first_env(*names: str) -> str:
    """Return the first non-empty trimmed value among ``names``."""
    for name in names:
        v = os.environ.get(name, "")
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def api_key_for_provider(provider_id: str) -> str:
    """Unified key lookup so users can use either SusCheck names or upstream SDK names."""
    p = provider_id.lower().strip()
    # (SUSCHECK_AI_KEY first everywhere, then ecosystem conventions)
    chains: dict[str, tuple[str, ...]] = {
        "openai": ("SUSCHECK_AI_KEY", "OPENAI_API_KEY"),
        "groq": ("SUSCHECK_AI_KEY", "GROQ_API_KEY"),
        "anthropic": ("SUSCHECK_AI_KEY", "ANTHROPIC_API_KEY"),
        "openrouter": ("SUSCHECK_AI_KEY", "OPENROUTER_API_KEY"),
        "mistral": ("SUSCHECK_AI_KEY", "MISTRAL_API_KEY"),
        "cerebras": ("SUSCHECK_AI_KEY", "CEREBRAS_API_KEY"),
        "sambanova": ("SUSCHECK_AI_KEY", "SAMBANOVA_API_KEY"),
        "google": ("SUSCHECK_AI_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"),
        "gemini": ("SUSCHECK_AI_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"),
    }
    return first_env(*chains.get(p, ("SUSCHECK_AI_KEY",)))
