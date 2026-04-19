# SusCheck Scan Profiles

This document defines the built-in scan profiles and their exact defaults.

## Built-In Profiles

1. `default`
- AI triage: enabled
- VirusTotal: enabled
- Dependency-Check: disabled
- MCP dynamic: disabled
- Purpose: balanced baseline for most users.

2. `deep`
- AI triage: enabled
- VirusTotal: enabled
- Dependency-Check: enabled
- MCP dynamic: enabled
- Purpose: broader/deeper coverage when you can afford longer scan time.

3. `fast`
- AI triage: disabled
- VirusTotal: disabled
- Dependency-Check: disabled
- MCP dynamic: disabled
- Purpose: fastest pass for quick triage loops.

4. `mcp-hardening`
- AI triage: enabled
- VirusTotal: enabled
- Dependency-Check: disabled
- MCP dynamic: enabled
- Purpose: focus on MCP hardening paths, including optional runtime observation.

## Toggle Precedence

Explicit toggles override profile defaults:

1. `--ai` / `--no-ai`
2. `--vt` / `--no-vt`
3. `--dependency-check` / `--no-dependency-check`
4. `--mcp-dynamic` / `--no-mcp-dynamic`

Rule used by CLI:
1. explicit enable > explicit disable > profile default.

## Are Custom Profiles Supported?

Not yet. Custom user-defined profiles are planned for a later milestone.
For now, use one of the built-ins and combine with explicit toggles.

## Examples

```bash
# Balanced baseline
suscheck scan ./project --profile default

# Deeper coverage
suscheck scan ./project --profile deep

# Fast feedback
suscheck scan ./project --profile fast --no-ai

# MCP-focused hardening
suscheck scan ./mcp.json --profile mcp-hardening
```
