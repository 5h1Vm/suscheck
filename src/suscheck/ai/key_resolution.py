"""Resolve API keys: prefer provider-specific env names, then ``SUSCHECK_AI_KEY`` fallback."""

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
    # Provider-specific key first, then SUSCHECK_AI_KEY fallback.
    chains: dict[str, tuple[str, ...]] = {
        "openai": ("OPENAI_API_KEY", "SUSCHECK_AI_KEY"),
        "groq": ("GROQ_API_KEY", "SUSCHECK_AI_KEY"),
        "anthropic": ("ANTHROPIC_API_KEY", "SUSCHECK_AI_KEY"),
        "openrouter": ("OPENROUTER_API_KEY", "SUSCHECK_AI_KEY"),
        "mistral": ("MISTRAL_API_KEY", "SUSCHECK_AI_KEY"),
        "cerebras": ("CEREBRAS_API_KEY", "SUSCHECK_AI_KEY"),
        "sambanova": ("SAMBANOVA_API_KEY", "SUSCHECK_AI_KEY"),
        "google": ("GEMINI_API_KEY", "GOOGLE_API_KEY", "SUSCHECK_AI_KEY"),
        "gemini": ("GEMINI_API_KEY", "GOOGLE_API_KEY", "SUSCHECK_AI_KEY"),
    }
    return first_env(*chains.get(p, ("SUSCHECK_AI_KEY",)))
