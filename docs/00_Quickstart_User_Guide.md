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

## 4. AI-Powered "Explain" Mode (New!)
If a file is flagged as CAUTION or HOLD, and you don't understand why, use the **explain** command. This uses behavioral AI to analyze the code and scanners' findings to tell you *exactly* what the file is doing in plain English.

```bash
# Get a plain-English behavioral analysis of a file
suscheck explain suspicious_script.py
```

## 5. Generating Audit Reports
For professional audits or team sharing, you can generate premium reports:

```bash
# Generate a dark-mode HTML audit report
suscheck scan suspicious_file.py --format html --output report.html

# Export scan data to JSON or Markdown
suscheck scan suspicious_file.py --format json --output data.json
suscheck scan suspicious_file.py --format md --output report.md
```

## 6. Other useful commands
* **`suscheck trust some-package`** — PyPI-focused supply chain signals (typosquatting hints, maintenance/yanked-style checks, deps.dev context).
* **MCP config files** — If you save a Cursor-style JSON with `mcpServers`, run `suscheck scan path/to/mcp.json` to run the **static MCP scanner**.

## 7. Helpful flags
* `suscheck scan -h` — all `scan` options.
* `suscheck version` — Python version, which env vars are set, and tool status.
* `--upload-vt` — **Use with caution:** uploads the file to VirusTotal (becomes public there).

For more details, see [03_CLI_Reference.md](03_CLI_Reference.md).
