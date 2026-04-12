"""MCP static scanner — parses MCP client/manifest JSON and flags over-privileged tools.

Targets JSON documents that declare MCP servers (e.g. Cursor/VS Code style ``mcpServers``)
or embedded ``tools`` metadata. Rules load from ``rules/mcp.toml``.
"""

from __future__ import annotations

import json
import logging
import re
import sys
import time
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from suscheck.core.finding import Finding, FindingType, Severity
from suscheck.modules.base import ModuleResult, ScannerModule

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_MCP_SNIFF_RE = re.compile(r'"mcpServers"\s*:')
_MCP_CONFIG_NAMES = frozenset(
    name.lower() for name in ("mcp-config.json", "mcp.json", "mcp_config.json")
)


def _rules_path() -> Path:
    p = _PROJECT_ROOT / "rules" / "mcp.toml"
    if p.exists():
        return p
    cwd = Path.cwd() / "rules" / "mcp.toml"
    return cwd


def _load_mcp_toml() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return (restricted_tools with compiled name_pattern, prompt_rules with compiled regex)."""
    path = _rules_path()
    restricted: list[dict[str, Any]] = []
    prompts: list[dict[str, Any]] = []
    if not path.is_file():
        logger.warning("MCP rules not found at %s", path)
        return restricted, prompts
    try:
        with path.open("rb") as f:
            data = tomllib.load(f)
    except OSError as e:
        logger.error("Failed to read MCP rules: %s", e)
        return restricted, prompts

    for entry in data.get("restricted_tools") or []:
        if not isinstance(entry, dict):
            continue
        pat = entry.get("name_pattern", "")
        try:
            entry = dict(entry)
            entry["_name_re"] = re.compile(pat)
            restricted.append(entry)
        except re.error as e:
            logger.error("Invalid name_pattern in MCP rule %s: %s", entry.get("id"), e)

    for entry in data.get("prompt_rules") or []:
        if not isinstance(entry, dict):
            continue
        pat = entry.get("regex", "")
        try:
            entry = dict(entry)
            entry["_prompt_re"] = re.compile(pat)
            prompts.append(entry)
        except re.error as e:
            logger.error("Invalid regex in MCP prompt rule %s: %s", entry.get("id"), e)

    return restricted, prompts


def _looks_like_mcp_json_file(path: Path) -> bool:
    if path.name.lower() in _MCP_CONFIG_NAMES:
        return True
    try:
        head = path.read_text(encoding="utf-8", errors="ignore")[:8192]
    except OSError:
        return False
    return bool(_MCP_SNIFF_RE.search(head))


def _collect_tool_names(obj: Any, out: list[str]) -> None:
    if isinstance(obj, dict):
        if "tools" in obj and isinstance(obj["tools"], list):
            for item in obj["tools"]:
                if isinstance(item, dict):
                    name = item.get("name")
                    if isinstance(name, str) and name.strip():
                        out.append(name.strip())
        for v in obj.values():
            _collect_tool_names(v, out)
    elif isinstance(obj, list):
        for item in obj:
            _collect_tool_names(item, out)


class MCPScanner(ScannerModule):
    """Static analysis for MCP configuration / manifest JSON files."""

    def __init__(self) -> None:
        self._restricted_tools, self._prompt_rules = _load_mcp_toml()

    @property
    def name(self) -> str:
        return "mcp"

    def can_handle(self, artifact_type: str, file_path: str = "") -> bool:
        if not file_path:
            return False
        p = Path(file_path)
        if not p.is_file():
            return False
        if artifact_type.lower() == "mcp_server":
            return True
        if p.suffix.lower() == ".json" and _looks_like_mcp_json_file(p):
            return True
        return False

    def scan(self, target: str, config: dict | None = None) -> ModuleResult:
        start = time.time()
        errors: list[str] = []
        findings: list[Finding] = []

        path = Path(target)
        if not path.is_file():
            return ModuleResult(
                module_name=self.name,
                findings=[],
                scan_duration=time.time() - start,
                error="Target is not a valid file.",
            )

        try:
            raw = path.read_text(encoding="utf-8", errors="strict")
        except UnicodeDecodeError:
            try:
                raw = path.read_text(encoding="utf-8", errors="ignore")
            except OSError as e:
                return ModuleResult(
                    module_name=self.name,
                    findings=[],
                    scan_duration=time.time() - start,
                    error=f"Cannot read file: {e}",
                )
        except OSError as e:
            return ModuleResult(
                module_name=self.name,
                findings=[],
                scan_duration=time.time() - start,
                error=f"Cannot read file: {e}",
            )

        try:
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
                error="MCP manifest must be a JSON object at the root.",
            )

        findings.extend(self._scan_server_configs(data, str(path)))
        findings.extend(self._scan_tool_names(data, str(path)))
        findings.extend(self._scan_prompt_rules(raw, str(path)))

        return ModuleResult(
            module_name=self.name,
            findings=findings,
            metadata={"rules_file": str(_rules_path())},
            scan_duration=time.time() - start,
            error="; ".join(errors) if errors else None,
        )

    def _scan_server_configs(self, data: dict[str, Any], file_path: str) -> list[Finding]:
        findings: list[Finding] = []
        servers = data.get("mcpServers")
        if servers is None and "servers" in data:
            servers = data.get("servers")
        if not isinstance(servers, dict):
            return findings

        for srv_name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            cmd = cfg.get("command")
            args = cfg.get("args") or []
            url = cfg.get("url")

            if isinstance(cmd, str) and cmd.strip():
                base = Path(cmd.strip()).name.lower()
                shells = frozenset(
                    ("bash", "sh", "zsh", "fish", "cmd", "powershell.exe", "pwsh", "pwsh.exe")
                )
                if base in shells or "powershell" in cmd.lower():
                    findings.append(
                        Finding(
                            module=self.name,
                            finding_id=f"MCP-SHELL-{srv_name}"[:48],
                            title=f"MCP server '{srv_name}' uses a shell as transport command",
                            description=(
                                "Launching MCP through an interactive shell increases the risk of "
                                "argument injection and makes the agent boundary harder to reason about."
                            ),
                            severity=Severity.HIGH,
                            finding_type=FindingType.MCP_OVERPRIVILEGE,
                            confidence=0.80,
                            file_path=file_path,
                            context="config",
                            mitre_ids=["T1059"],
                            evidence={"server": srv_name, "command": cmd},
                        )
                    )

            if isinstance(args, list):
                flat = [str(a) for a in args]
                for i, a in enumerate(flat):
                    if a in ("-c", "/c", "-Command", "-EncodedCommand") and i + 1 < len(flat):
                        findings.append(
                            Finding(
                                module=self.name,
                                finding_id=f"MCP-INLINE-{srv_name}"[:48],
                                title=f"MCP server '{srv_name}' passes inline script arguments",
                                description=(
                                    "Inline script flags (-c, /c, -Command, etc.) on the MCP server "
                                    "process can carry arbitrary code alongside model-driven behavior."
                                ),
                                severity=Severity.HIGH,
                                finding_type=FindingType.MCP_OVERPRIVILEGE,
                                confidence=0.78,
                                file_path=file_path,
                                context="config",
                                mitre_ids=["T1059"],
                                evidence={"server": srv_name, "flag": a},
                            )
                        )
                joined = " ".join(flat)
                if "server-filesystem" in joined or "@modelcontextprotocol/server-filesystem" in joined:
                    risky_roots = ("/", "C:\\", "C:/", "c:\\", "c:/")
                    if any(r in flat for r in risky_roots):
                        findings.append(
                            Finding(
                                module=self.name,
                                finding_id=f"MCP-FSROOT-{srv_name}"[:48],
                                title=f"MCP filesystem server '{srv_name}' targets a filesystem root",
                                description=(
                                    "The official filesystem MCP server is scoped by its root path. "
                                    "Mounting '/' or a drive root gives the agent broad read access."
                                ),
                                severity=Severity.CRITICAL,
                                finding_type=FindingType.MCP_OVERPRIVILEGE,
                                confidence=0.85,
                                file_path=file_path,
                                context="config",
                                mitre_ids=["T1005"],
                                evidence={"server": srv_name, "args_sample": flat[:12]},
                            )
                        )

            if isinstance(url, str) and url.strip().startswith(("http://", "https://")):
                findings.append(
                    Finding(
                        module=self.name,
                        finding_id=f"MCP-REMOTE-{srv_name}"[:48],
                        title=f"MCP server '{srv_name}' uses remote HTTP/SSE transport",
                        description=(
                            "Remote MCP endpoints shift trust to a network party. Verify authenticity, "
                            "TLS, and data handling before connecting an agent."
                        ),
                        severity=Severity.MEDIUM,
                        finding_type=FindingType.SUSPICIOUS_BEHAVIOR,
                        confidence=0.55,
                        file_path=file_path,
                        context="config",
                        mitre_ids=["T1071"],
                        evidence={"server": srv_name, "url": url[:200]},
                    )
                )

        return findings

    def _scan_tool_names(self, data: dict[str, Any], file_path: str) -> list[Finding]:
        names: list[str] = []
        _collect_tool_names(data, names)
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for tool_name in names:
            for rule in self._restricted_tools:
                rgx: re.Pattern[str] = rule["_name_re"]
                if not rgx.search(tool_name):
                    continue
                key = (rule.get("id", ""), tool_name)
                if key in seen:
                    continue
                seen.add(key)
                try:
                    sev = Severity(str(rule.get("severity", "high")).lower())
                except ValueError:
                    sev = Severity.HIGH
                try:
                    ftype = FindingType(str(rule.get("finding_type", "mcp_overprivilege")).lower())
                except ValueError:
                    ftype = FindingType.MCP_OVERPRIVILEGE
                fid = f"{rule.get('id', 'MCP-TOOL')}:{tool_name}"
                findings.append(
                    Finding(
                        module=self.name,
                        finding_id=fid[:72],
                        title=str(rule.get("title", "Risky MCP tool")),
                        description=str(
                            rule.get("description", "Restricted tool name pattern matched.")
                        ),
                        severity=sev,
                        finding_type=ftype,
                        confidence=float(rule.get("confidence", 0.7)),
                        file_path=file_path,
                        context="config",
                        mitre_ids=list(rule.get("mitre_ids", [])),
                        evidence={"tool_name": tool_name, "rule_id": rule.get("id")},
                    )
                )
        return findings

    def _scan_prompt_rules(self, raw_text: str, file_path: str) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self._prompt_rules:
            rgx: re.Pattern[str] = rule["_prompt_re"]
            m = rgx.search(raw_text)
            if not m:
                continue
            try:
                sev = Severity(str(rule.get("severity", "high")).lower())
            except ValueError:
                sev = Severity.HIGH
            try:
                ftype = FindingType(str(rule.get("finding_type", "prompt_injection")).lower())
            except ValueError:
                ftype = FindingType.PROMPT_INJECTION
            findings.append(
                Finding(
                    module=self.name,
                    finding_id=str(rule.get("id", "MCP-PROMPT")),
                    title=str(rule.get("title", "Prompt injection pattern")),
                    description=str(rule.get("description", "Suspicious text matched.")),
                    severity=sev,
                    finding_type=ftype,
                    confidence=float(rule.get("confidence", 0.7)),
                    file_path=file_path,
                    context="config",
                    mitre_ids=list(rule.get("mitre_ids", [])),
                    evidence={"match_span": m.group(0)[:120], "rule_id": rule.get("id")},
                )
            )
        return findings
