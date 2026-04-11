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
SusCheck works offline out of the box, but it is **10x more powerful** if you provide it with API keys. It uses these to query live threat intelligence.

Create a `.env` file in the folder where you run the tool:
```bash
# Get this for free at virustotal.com
SUSCHECK_VT_KEY="your_api_key_here"

# (More APIs coming soon in future increments!)
```

## 3. Reading the Output
SusCheck will give you a **Platform Risk Index (PRI)** score out of 100.
* **0-15 (CLEAR):** The file looks completely normal.
* **16-40 (CAUTION):** Found some weird code. Be careful.
* **41-70 (HOLD):** Very suspicious indicators (like hidden base64 or obfuscation). Review it yourself.
* **71-100 (ABORT):** Almost certainly malicious. Do not run it.

It also has a **🔍 Needs Human Review** section. If the scanner finds something weird but can't prove it's evil (like a connection to a Telegram bot API), it will flag it here for you to manually inspect.

## 4. Helpful Flags
* `suscheck scan -h` : Shows you all the options.
* `suscheck version` : Shows you exactly which APIs are successfully plugged in.
* `--upload-vt` : **Use with Caution!** If you scan a file and VirusTotal has never seen it before, you can use this flag to upload the actual file to VirusTotal's servers for deep analysis. *Note: this makes the file public to security researchers on VirusTotal.*
