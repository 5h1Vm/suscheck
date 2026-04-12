"""Tests for MCP dynamic (Docker) observer — mocked, no daemon required."""

import json
from unittest.mock import MagicMock, patch

from suscheck.core.finding import FindingType
from suscheck.modules.mcp_dynamic import (
    MIN_TX_DELTA_BYTES,
    MCPDynamicScanner,
    extract_mcp_servers,
    infer_base_image,
    observe_stdio_server_in_docker,
)


def test_extract_mcp_servers():
    data = {"mcpServers": {"a": {"command": "npx"}, "b": "bad"}}
    out = extract_mcp_servers(data)
    assert "a" in out and isinstance(out["a"], dict)
    assert "b" not in out


def test_infer_base_image():
    assert infer_base_image("/usr/bin/npx") == "node:20-bookworm-slim"
    assert infer_base_image("python3") == "python:3.12-slim"
    assert infer_base_image("/bin/unknown-tool") is None


def test_observe_docker_unavailable():
    with patch("suscheck.modules.mcp_dynamic._docker_client", side_effect=ImportError("no docker")):
        findings, meta = observe_stdio_server_in_docker("s", "npx", ["-y", "x"], timeout_sec=5)
    assert findings == []
    assert "error" in meta


@patch("suscheck.modules.mcp_dynamic._docker_client")
def test_observe_network_delta_finding(mock_from_env):
    client = MagicMock()
    mock_from_env.return_value = client
    client.ping.return_value = None

    ctr = MagicMock()
    ctr.short_id = "abc123"
    ctr.status = "running"
    ctr.attrs = {"State": {"ExitCode": 0}}
    ctr.reload.side_effect = lambda *a, **k: None

    ctr.stats.side_effect = [
        {"networks": {"eth0": {"tx_bytes": 100}}},
        {"networks": {"eth0": {"tx_bytes": 20000}}},
    ]
    ctr.logs.return_value = b"ok\n"
    client.containers.run.return_value = ctr

    findings, meta = observe_stdio_server_in_docker("srv", "npx", ["-y", "pkg"], timeout_sec=2)
    assert meta.get("tx_bytes_delta", 0) >= MIN_TX_DELTA_BYTES
    assert any(f.finding_type == FindingType.SUSPICIOUS_BEHAVIOR for f in findings)


def test_dynamic_scanner_skips_url_only_servers(tmp_path):
    cfg = {"mcpServers": {"remote": {"url": "https://example.com/mcp"}}}
    p = tmp_path / "mcp.json"
    p.write_text(json.dumps(cfg), encoding="utf-8")
    res = MCPDynamicScanner(observe_seconds=3).scan(str(p))
    assert res.error is None
    assert res.findings == []
    assert any(o.get("skip") == "url_transport" for o in res.metadata.get("observations", []))


@patch("suscheck.modules.mcp_dynamic.observe_stdio_server_in_docker")
def test_dynamic_scanner_runs_stdio_servers(mock_obs, tmp_path):
    mock_obs.return_value = ([], {"server": "x", "ok": True})
    cfg = {"mcpServers": {"x": {"command": "npx", "args": ["-y", "pkg"]}}}
    p = tmp_path / "mcp.json"
    p.write_text(json.dumps(cfg), encoding="utf-8")
    res = MCPDynamicScanner(observe_seconds=3).scan(str(p))
    assert mock_obs.called
    assert res.error is None
