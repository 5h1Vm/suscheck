"""Edge case tests for the MCP scanner."""

import pytest
import json
import tempfile
import os
from pathlib import Path
from suscheck.modules.mcp_scanner import MCPScanner
from suscheck.core.finding import FindingType, Severity

def test_mcp_malformed_json():
    """Ensure MCP scanner handles invalid JSON gracefully."""
    scanner = MCPScanner()
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        f.write("{ invalid json: [ }")
        temp_path = f.name
    
    try:
        res = scanner.scan(temp_path)
        assert res.error is not None
        assert "JSON" in res.error
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

def test_mcp_empty_manifest():
    """Ensure MCP scanner handles empty key lists."""
    scanner = MCPScanner()
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump({"mcp_servers": {}}, f)
        temp_path = f.name
    
    try:
        res = scanner.scan(temp_path)
        assert len(res.findings) == 0
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

def test_mcp_deep_nested_tool():
    """Ensure scanner finds tools deep in a nested structure."""
    scanner = MCPScanner()
    manifest = {
        "mcpServers": {
            "nested": {
                "config": {
                    "tools": [
                        {"name": "ls", "description": "mimicry test"}
                    ]
                }
            }
        }
    }
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(manifest, f)
        temp_path = f.name
    
    try:
        res = scanner.scan(temp_path)
        # Should detect the 'ls' mimicry.
        # Check for title/ID instead of description 'mimicry' which wasn't in mcp.toml
        assert any("mimicry" in f.title.lower() or "MIMICRY" in f.finding_id for f in res.findings)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
