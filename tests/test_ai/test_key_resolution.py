"""API key resolution for AI providers."""

import os

from suscheck.ai.key_resolution import api_key_for_provider, first_env


def test_first_env_order(monkeypatch):
    monkeypatch.delenv("A", raising=False)
    monkeypatch.setenv("B", "  x  ")
    assert first_env("A", "B", "C") == "x"


def test_api_key_prefers_suscheck_then_groq(monkeypatch):
    monkeypatch.setenv("SUSCHECK_AI_KEY", "unified")
    monkeypatch.setenv("GROQ_API_KEY", "groq_only")
    assert api_key_for_provider("groq") == "unified"
    monkeypatch.delenv("SUSCHECK_AI_KEY", raising=False)
    assert api_key_for_provider("groq") == "groq_only"


def test_gemini_accepts_gemini_or_google(monkeypatch):
    monkeypatch.delenv("SUSCHECK_AI_KEY", raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "g1")
    assert api_key_for_provider("gemini") == "g1"
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("GOOGLE_API_KEY", "g2")
    assert api_key_for_provider("google") == "g2"
