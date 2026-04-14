"""Centralized Configuration Manager for SusCheck. 
Prioritizes Environment Variables for all settings.
"""

import os
from pathlib import Path
from typing import Any, Dict, Optional

class ConfigManager:
    """Manages SusCheck settings with pure Environment Variable overrides."""

    DEFAULT_CONFIG = {
        "reporting": {
            "default_dir": "./reports",
            "format": "terminal",
            "timestamped": True
        },
        "ai": {
            "primary_model": "groq:llama3-70b-8192",
            "fallback_models": ["anthropic:claude-3-haiku", "gemini:gemini-1.5-flash"],
            "triage_enabled": True,
            "explain_enabled": True
        },
        "scanners": {
            "mcp_dynamic": {
                "timeout": 300,
                "allow_docker": True
            },
            "code": {
                "max_file_size_mb": 5,
                "recursive": True
            },
            "scanning": {
                "max_file_size_mb": 50
            }
        }
    }

    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize with defaults. config_path is retained for 
        API compatibility but ignored in favor of .env.
        """
        self._config = self.DEFAULT_CONFIG.copy()

    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get a value by dot notation (e.g. 'ai.primary_model').
        Checks for environment variable overrides first:
        Format: SUSCHECK_{SECTION}_{KEY} e.g. SUSCHECK_AI_PRIMARY_MODEL
        """
        # 1. Check for specific API Key requests
        if key_path.startswith("api_keys."):
            service = key_path.split(".")[1]
            env_service = "VT" if service == "virustotal" else service.upper()
            env_key = f"SUSCHECK_{env_service}_KEY"
            
            if env_key in os.environ:
                return os.environ[env_key]
            if key_path == "api_keys.github_token":
                return os.environ.get("SUSCHECK_GITHUB_TOKEN")

        # 2. Check for General Configuration Overrides
        # Strategy: SUSCHECK_AI_PRIMARY_MODEL -> ai.primary_model
        env_key = f"SUSCHECK_{key_path.replace('.', '_').upper()}"
        if env_key in os.environ:
            val = os.environ[env_key]
            # Simple type conversion for known defaults
            if val.lower() in ("true", "false"):
                return val.lower() == "true"
            try:
                if "." in val:
                    return float(val)
                return int(val)
            except ValueError:
                return val

        # 3. Traverse internal defaults
        val = self._config
        for part in key_path.split("."):
            if isinstance(val, dict) and part in val:
                val = val[part]
            else:
                # Direct fallback for API keys if not in config
                if key_path.startswith("api_keys."):
                    return os.environ.get(f"SUSCHECK_{key_path.split('.')[-1].upper()}_KEY", default)
                return default
        
        return val

    @property
    def api_keys(self) -> Dict[str, str]:
        """Returns all resolved API keys from environment."""
        providers = ["virustotal", "abuseipdb", "groq", "anthropic", "openai", "gemini", "github_token", "nvd"]
        keys = {}
        for p in providers:
            val = self.get(f"api_keys.{p}")
            if val:
                keys[p] = val
        return keys
