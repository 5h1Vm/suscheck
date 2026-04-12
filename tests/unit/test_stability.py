import pytest
import os
from unittest.mock import MagicMock
from suscheck.ai.key_resolution import api_key_for_provider
from suscheck.core.auto_detector import AutoDetector, Language

def test_key_resolution_priority():
    """Verify that specific provider keys take precedence over generic SUSCHECK_AI_KEY."""
    os.environ["SUSCHECK_AI_KEY"] = "generic_key"
    os.environ["GROQ_API_KEY"] = "groq_specific"
    
    # Reset any cached state if necessary (assuming it reads from env each time)
    key = api_key_for_provider("groq")
    assert key == "groq_specific"
    
    # Fallback check
    os.environ.pop("GROQ_API_KEY", None)
    key = api_key_for_provider("groq")
    assert key == "generic_key"

def test_batch_detection_heuristics():
    """Verify that generic text files aren't flagged as Batch malware."""
    detector = AutoDetector()
    
    # A generic text file with .bat extension but no markers
    with open("dummy.bat", "w") as f:
        f.write("This is a normal text file about batch processing.\n It has no commands.")
    
    artifact = detector.detect("dummy.bat")
    # Should be downgraded to UNKNOWN because it lacks @echo/set/goto etc.
    assert artifact.language == Language.UNKNOWN

    # A real batch file
    with open("real.bat", "w") as f:
        f.write("@echo off\nset x=1\necho %x%")
    
    artifact = detector.detect("real.bat")
    assert artifact.language == Language.BATCH

    # Cleanup
    os.remove("dummy.bat")
    os.remove("real.bat")

def test_mcp_rule_path():
    """Verify that MCPScanner can find its rules file."""
    from suscheck.modules.mcp.scanner import _rules_path
    path = _rules_path()
    # If the fix works, path should point to a valid file
    assert path.exists()
    assert path.name == "mcp.toml"
