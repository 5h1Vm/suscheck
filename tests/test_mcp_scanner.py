from __future__ import annotations

import json
from pathlib import Path

from suscheck.modules.mcp.scanner import MCPScanner


def test_mcp_scanner_auth_rules_detect_insecure_and_missing_auth(tmp_path: Path) -> None:
    target = tmp_path / "mcp.json"
    target.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "remoteA": {
                        "url": "http://example.com/sse",
                        "command": "node",
                        "args": ["server.js"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    scanner = MCPScanner()
    result = scanner.scan(str(target))
    ids = {finding.finding_id for finding in result.findings}

    assert any(fid.startswith("MCP-AUTH-INSECURE-TRANSPORT-") for fid in ids)
    assert any(fid.startswith("MCP-AUTH-MISSING-") for fid in ids)


def test_mcp_scanner_auth_rules_detect_anonymous_wildcard_and_weak_tokens(tmp_path: Path) -> None:
    target = tmp_path / "mcp.json"
    target.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "remoteB": {
                        "url": "https://mcp.example.com/sse",
                        "headers": {"Authorization": "Bearer hardcoded-token-value"},
                        "auth": {
                            "type": "anonymous",
                            "allowAnonymous": True,
                            "scopes": ["*"],
                            "token": "hardcoded-secret-token",
                        },
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    scanner = MCPScanner()
    result = scanner.scan(str(target))
    ids = {finding.finding_id for finding in result.findings}

    assert any(fid.startswith("MCP-AUTH-ANONYMOUS-") for fid in ids)
    assert any(fid.startswith("MCP-AUTH-ALLOW-ANON-") for fid in ids)
    assert any(fid.startswith("MCP-AUTH-WILDCARD-SCOPE-") for fid in ids)
    assert any(fid.startswith("MCP-AUTH-WEAK-TOKEN-") for fid in ids)
