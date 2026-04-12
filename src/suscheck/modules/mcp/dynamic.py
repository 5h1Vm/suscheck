"""MCP dynamic observer — optional Docker-backed runtime observation (Increment 12).

Requires: Docker daemon reachable + ``docker`` Python package (optional extra).
If unavailable, scan returns empty findings with metadata explaining skip — no fake results.
"""

from __future__ import annotations

import json
import logging
import re
import shlex
import time
from pathlib import Path
from typing import Any

from suscheck.core.finding import Finding, FindingType, Severity
from suscheck.modules.base import ModuleResult, ScannerModule

logger = logging.getLogger(__name__)

# Default observation window (seconds) per Checkpoint 1a
DEFAULT_OBSERVE_SECONDS = 60
# Egress threshold (bytes TX delta) to flag as notable (excludes absolute zero noise)
MIN_TX_DELTA_BYTES = 4096
_LOG_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)


def extract_mcp_servers(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    servers = data.get("mcpServers")
    if servers is None and "servers" in data:
        servers = data.get("servers")
    if not isinstance(servers, dict):
        return {}
    return {k: v for k, v in servers.items() if isinstance(v, dict)}


def infer_base_image(command: str) -> str | None:
    """Pick a reasonable image for ``command`` (stdio MCP servers are usually node or python)."""
    c = (command or "").strip().lower()
    base = Path(c).name.lower()
    if base in ("npx", "npm", "node", "bun", "deno"):
        return "node:20-bookworm-slim"
    if base in ("python", "python3", "uv", "uvx"):
        return "python:3.12-slim"
    return None


def _docker_client():
    import docker

    return docker.from_env()


def _container_net_tx(stats: dict[str, Any]) -> int:
    nets = stats.get("networks") or {}
    total = 0
    for iface in nets.values():
        if isinstance(iface, dict):
            total += int(iface.get("tx_bytes") or 0)
    return total


def observe_stdio_server_in_docker(
    server_name: str,
    command: str,
    args: list[Any],
    *,
    timeout_sec: int = DEFAULT_OBSERVE_SECONDS,
    file_path: str = "",
) -> tuple[list[Finding], dict[str, Any]]:
    """Run ``command`` + ``args`` inside a short-lived container; collect stats and logs.

    Returns (findings, debug_metadata). On failure, findings may be empty and metadata has ``error``.
    """
    meta: dict[str, Any] = {"server": server_name, "command": command, "args": list(map(str, args))}
    findings: list[Finding] = []

    try:
        client = _docker_client()
        client.ping()
    except Exception as e:
        logger.warning("Docker unavailable for MCP dynamic: %s", e)
        meta["status"] = "SKIPPED"
        meta["error"] = f"docker_unavailable: {e}"
        return findings, meta

    image = infer_base_image(command)
    if not image:
        meta["skip"] = "no_image_inference"
        return findings, meta

    cmd_parts = [str(command)] + [str(a) for a in args]
    inner = " ".join(shlex.quote(x) for x in cmd_parts)
    shell_line = f"timeout {timeout_sec}s {inner} 2>&1 || true"

    container: Any = None
    try:
        container = client.containers.run(
            image,
            command=["/bin/sh", "-c", shell_line],
            detach=True,
            mem_limit="512m",
            pids_limit=128,
            network_mode="bridge",
            stdout=True,
            stderr=True,
        )
        meta["container_id"] = container.short_id
        meta["image"] = image

        time.sleep(2.0)
        try:
            s_early = container.stats(stream=False)
            tx_early = _container_net_tx(s_early)
        except Exception:
            tx_early = 0

        # Remaining observation window
        end = time.time() + max(0, timeout_sec - 2)
        while time.time() < end:
            container.reload()
            if container.status != "running":
                break
            time.sleep(3.0)

        try:
            s_late = container.stats(stream=False)
            tx_late = _container_net_tx(s_late)
        except Exception:
            tx_late = tx_early

        delta_tx = max(0, tx_late - tx_early)
        meta["tx_bytes_delta"] = delta_tx

        if delta_tx >= MIN_TX_DELTA_BYTES:
            findings.append(
                Finding(
                    module="mcp_dynamic",
                    finding_id=f"MCP-DYN-NET-{server_name}"[:48],
                    title=f"MCP server '{server_name}' showed outbound network I/O in container",
                    description=(
                        f"During a {timeout_sec}s isolated Docker run, transmitted bytes increased by "
                        f"{delta_tx} (threshold {MIN_TX_DELTA_BYTES}). This may include package installs "
                        f"(e.g. npx) or runtime callbacks — review logs and intent."
                    ),
                    severity=Severity.MEDIUM,
                    finding_type=FindingType.SUSPICIOUS_BEHAVIOR,
                    confidence=0.55,
                    file_path=file_path or None,
                    context="config",
                    mitre_ids=["T1071"],
                    evidence={"server": server_name, "tx_delta": delta_tx, "image": image},
                )
            )

        try:
            log_b = container.logs(tail=200)
            log_text = log_b.decode("utf-8", errors="replace")
        except Exception:
            log_text = ""

        meta["log_tail_chars"] = len(log_text)
        urls = _LOG_URL_RE.findall(log_text)
        if urls:
            uniq = list(dict.fromkeys(urls))[:8]
            findings.append(
                Finding(
                    module="mcp_dynamic",
                    finding_id=f"MCP-DYN-URL-{server_name}"[:48],
                    title=f"MCP server '{server_name}' referenced URLs in container logs",
                    description=(
                        "URLs appeared in stdout/stderr during observation. Verify they are expected "
                        "for this MCP server (registry, API, or documentation)."
                    ),
                    severity=Severity.LOW,
                    finding_type=FindingType.NETWORK_INDICATOR,
                    confidence=0.50,
                    file_path=file_path or None,
                    context="config",
                    mitre_ids=["T1071"],
                    evidence={"server": server_name, "urls": uniq},
                )
            )

        # --- New: Filesystem Delta Monitoring (Checkpoint 1a Stage 2) ---
        try:
            fs_diff = container.diff()
            if fs_diff:
                meta["fs_diff_count"] = len(fs_diff)
                sensitive_changes = []
                for change in fs_diff:
                    path = change.get("Path", "")
                    # Flag modifications to sensitive system paths or new binaries
                    if any(p in path for p in ["/etc/", "/usr/bin/", "/bin/", "/root/", ".ssh"]):
                         sensitive_changes.append(path)
                
                if sensitive_changes:
                    findings.append(
                        Finding(
                            module="mcp_dynamic",
                            finding_id=f"MCP-DYN-FS-{server_name}"[:48],
                            title=f"MCP server '{server_name}' modified sensitive system paths",
                            description=(
                                f"During observation, the server modified or created files in sensitive locations: "
                                f"{', '.join(sensitive_changes[:5])}. This level of filesystem access is highly "
                                f"suspicious for an MCP tool."
                            ),
                            severity=Severity.HIGH,
                            finding_type=FindingType.SUSPICIOUS_BEHAVIOR,
                            confidence=0.8,
                            file_path=file_path or None,
                            context="config",
                            mitre_ids=["T1083", "T1222"],
                            evidence={"sensitive_paths": sensitive_changes}
                        )
                    )
        except Exception as e:
            logger.debug(f"FS diff failed for {server_name}: {e}")

        # --- New: Process Monitoring (Checkpoint 1a Stage 2) ---
        try:
            top_info = container.top()
            if top_info:
                processes = top_info.get("Processes", [])
                meta["process_count"] = len(processes)
                meta["top_processes"] = processes[:10]
        except Exception:
            pass

        container.reload()
        exit_code = container.attrs.get("State", {}).get("ExitCode")
        meta["exit_code"] = exit_code
        if container.status == "running":
            findings.append(
                Finding(
                    module="mcp_dynamic",
                    finding_id=f"MCP-DYN-LONG-{server_name}"[:48],
                    title=f"MCP server '{server_name}' still running after observation window",
                    description=(
                        "The process did not exit before sampling ended (stdio servers often stay up). "
                        "This is informational; combine with static findings and manual review."
                    ),
                    severity=Severity.INFO,
                    finding_type=FindingType.REVIEW_NEEDED,
                    confidence=0.45,
                    file_path=file_path or None,
                    context="config",
                    mitre_ids=[],
                    evidence={"server": server_name, "status": container.status},
                )
            )
    except Exception as e:
        logger.warning("MCP dynamic observation failed for %s: %s", server_name, e)
        meta["error"] = str(e)
    finally:
        if container is not None:
            try:
                container.stop(timeout=5)
            except Exception:
                pass
            try:
                container.remove(force=True)
            except Exception:
                pass

    return findings, meta


class MCPDynamicScanner(ScannerModule):
    """Docker-backed observation for MCP stdio servers declared in a manifest JSON."""

    def __init__(self, observe_seconds: int = DEFAULT_OBSERVE_SECONDS):
        self._observe_seconds = observe_seconds

    @property
    def name(self) -> str:
        return "mcp_dynamic"

    def can_handle(self, artifact_type: str, file_path: str = "") -> bool:
        if not file_path:
            return False
        p = Path(file_path)
        if not p.is_file() or p.suffix.lower() != ".json":
            return False
        if artifact_type.lower() == "mcp_server":
            return True
        try:
            head = p.read_text(encoding="utf-8", errors="ignore")[:8192]
        except OSError:
            return False
        return '"mcpServers"' in head or '"mcp_servers"' in head

    def scan(self, target: str, config: dict | None = None) -> ModuleResult:
        start = time.time()
        cfg = config or {}
        timeout_sec = int(cfg.get("observe_seconds", self._observe_seconds))

        path = Path(target)
        if not path.is_file():
            return ModuleResult(
                module_name=self.name,
                findings=[],
                scan_duration=time.time() - start,
                error="Target is not a valid file.",
            )

        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            return ModuleResult(
                module_name=self.name,
                findings=[],
                scan_duration=time.time() - start,
                error=f"Invalid JSON: {e}",
            )

        if not isinstance(data, dict):
            return ModuleResult(
                module_name=self.name,
                findings=[],
                scan_duration=time.time() - start,
                error="Manifest must be a JSON object.",
            )

        servers = extract_mcp_servers(data)
        if not servers:
            return ModuleResult(
                module_name=self.name,
                findings=[],
                metadata={"mcp_dynamic": "no_stdio_servers_block"},
                scan_duration=time.time() - start,
            )

        all_findings: list[Finding] = []
        run_meta: list[dict[str, Any]] = []

        for srv_name, scfg in servers.items():
            if scfg.get("url"):
                # HTTP/SSE transport — not executed as local stdio in Docker
                run_meta.append({"server": srv_name, "skip": "url_transport"})
                continue
            cmd = scfg.get("command")
            if not isinstance(cmd, str) or not cmd.strip():
                continue

            args = scfg.get("args") or []
            if not isinstance(args, list):
                args = []

            findings, meta = observe_stdio_server_in_docker(
                srv_name,
                cmd.strip(),
                args,
                timeout_sec=timeout_sec,
                file_path=str(path),
            )
            all_findings.extend(findings)
            run_meta.append(meta)

        return ModuleResult(
            module_name=self.name,
            findings=all_findings,
            metadata={"observations": run_meta, "observe_seconds": timeout_sec},
            scan_duration=time.time() - start,
        )
