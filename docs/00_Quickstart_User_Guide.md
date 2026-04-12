# SusCheck: Quickstart User Guide

Welcome to **SusCheck**. This tool scans files, repositories, and packages *before* you run them, helping you catch malware and supply chain threats that standard code vulnerability scanners miss. 

## 1. How It Works
If you download a script from the internet, you shouldn't blindly run it. Instead, scan it:

```bash
# Scan a batch file, script, or executable
suscheck scan suspicious_script.sh
```

**What happens?**
1. **Tier 0:** It hashes the file and checks VirusTotal to see if security vendors already know it's malware.
2. **Tier 1:** It opens the file and hunts for hidden threats (Base64 payloads, sketchy URLs like `pastebin`, hardcoded AWS secrets, or dangerous commands like `eval()` and `Invoke-Expression`).

## 2. Setting Up Your APIs (Important!)
SusCheck works offline out of the box, but it is **much stronger** with API keys for live reputation data.

Create a `.env` file in the project root or your working directory (see `suscheck/.env.example` for the full list):
```bash
# Get this for free at virustotal.com
SUSCHECK_VT_KEY="your_api_key_here"

# Optional: AbuseIPDB for IP reputation on indicators extracted from files
# SUSCHECK_ABUSEIPDB_KEY="..."
```

Missing keys are skipped gracefully; the CLI does not crash.

## 3. Reading the Output
SusCheck will give you a **Platform Risk Index (PRI)** score out of 100.
* **0-15 (CLEAR):** The file looks completely normal.
* **16-40 (CAUTION):** Found some weird code. Be careful.
* **41-70 (HOLD):** Very suspicious indicators (like hidden base64 or obfuscation). Review it yourself.
* **71-100 (ABORT):** Almost certainly malicious. Do not run it.

It also has a **🔍 Needs Human Review** section. If the scanner finds something weird but can't prove it's evil (like a connection to a Telegram bot API), it will flag it here for you to manually inspect.

## 4. Other useful commands
* **`suscheck trust some-package`** — PyPI-focused supply chain signals (typosquatting hints, maintenance/yanked-style checks, deps.dev context). Use `-h` for options; npm is not implemented yet in the engine.
* **MCP config files** — If you save a Cursor-style JSON with `mcpServers`, run `suscheck scan path/to/mcp.json` to run the **static MCP scanner** (Increment 11).

## 5. Helpful flags
* `suscheck scan -h` — all `scan` options.
* `suscheck version` — Python version, which env vars are set (partial display), and whether tools like `gitleaks` / `semgrep` / `kics` are on your PATH.
* `--upload-vt` — **Use with caution:** uploads the file to VirusTotal (becomes public there).

For exact flag behavior (including options that are declared but not yet wired), see [03_CLI_Reference.md](03_CLI_Reference.md).
