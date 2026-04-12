# Rules Reference

SusCheck uses a flexible, machine-readable rule system to identify security threats across various artifact types. These rules are stored as TOML files and are loaded dynamically at runtime.

## 1. Static Analysis Rules (`src/suscheck/modules/code/layer2/`)

These rules are applied by the `CodeScanner` to analyze source files and web artifacts.

| File | Supported Language | Primary Detection Focus |
|------|-------------------|-------------------------|
| `universal.toml` | All | generic `curl\|bash`, basic encodings, universal C2 patterns. |
| `python.toml` | Python | `eval`, `exec`, suspicious imports (`base64`, `subprocess`), known malicious packages. |
| `javascript.toml` | JS/TS | Obfuscated strings, `eval`, `child_process`, suspicious network loads. |
| `php.toml` | PHP | **Web shells**, `eval`, `passthru`, `system`, preg_replace `/e` modifier. |
| `html.toml` | HTML/Web | **Hidden iframes (0/1px)**, randomized script sources, **phishing input fields**. |
| `bash.toml` | Shell/Bash | Reverse shells, disk wiping, credential harvesting. |
| `powershell.toml`| PowerShell | `IEX`, `EncodedCommand`, bypass flags, memory injections. |
| `batch.toml` | Batch/CMD | Obfuscated commands, registry manipulation, persistence. |

### Rule Structure
Each rule follows the standard SusCheck schema:
- **`id`**: Unique identifier (e.g., `FUNC-PHP-EVAL`).
- **`regex`**: The pattern to match.
- **`severity`**: `low`, `medium`, `high`, `critical`. Impact on PRI score.
- **`confidence`**: 0.0 to 1.0. Higher confidence reduces false positive noise.
- **`mitre_ids`**: Mapping to MITRE ATT&CK techniques (e.g., `["T1059"]`).

## 2. Infrastructure & Manifest Rules

- **Network (`network.toml`)**: Specialized patterns for identifying C2 domains and malicious IP indicators.
- **MCP (`mcp.toml`)**: Rules for Model Context Protocol manifests, specifically targeting risky tool declarations and prompt-injection patterns.

## 3. Threat Intelligence Mapping
SusCheck uses `mitre_mapping.json` to provide rich context for findings. When a rule matches, the associated `mitre_ids` are resolved to human-readable technique descriptions in the final report.
