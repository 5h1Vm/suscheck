# What Every File Does — Complete Reference

This document explains **every single file** in the SusCheck codebase — what it does, why it exists, and how it connects to the overall architecture from Checkpoint 1a.

---

## The Pipeline (How a Scan Actually Works)

When you run `suscheck scan some_file.sh`, here is exactly what happens:

1. **`cli.py`** receives the command, loads your `.env` API keys
2. **`auto_detector.py`** reads the file's magic bytes and determines it's a Bash script
3. **`hash_engine.py`** computes SHA-256, MD5, and SHA-1 hashes
4. **`virustotal.py`** takes that SHA-256 and asks VirusTotal: "Have you seen this file before?"
5. **`engine.py`** (Tier 0 orchestrator) checks if VT says it's malware. If 26+ detections → ABORT immediately.
6. **`code_scanner.py`** opens the file as text and runs 5 detectors on it:
   - `encoded_strings.py` → hunts for hidden Base64/hex payloads
   - `network_indicators.py` → extracts every IP, URL, and domain
   - `entropy.py` → measures randomness to find encrypted/obfuscated blobs
   - `credentials.py` → looks for hardcoded API keys and passwords
   - `dangerous_functions.py` → looks for eval(), exec(), curl|bash, IEX, etc.
7. **`abuseipdb.py`** takes the extracted IPs and checks them against the AbuseIPDB database
8. **`virustotal.py`** (again) takes the extracted URLs and checks them against VT
9. **`semgrep_runner.py`** runs the external Semgrep tool to find vulnerability patterns (SQLi, XSS, etc.)
10. **`cli.py`** computes a PRI score, determines verdict (CLEAR/CAUTION/HOLD/ABORT)
11. **`terminal.py`** renders everything beautifully in your terminal with Rich tables

---

## File-by-File Breakdown

### `src/suscheck/__init__.py` (5 lines)
**What it does:** Defines the version string (`__version__ = "0.1.0"`). That's it.
**Your idea:** ✅ Aligned.

### `src/suscheck/__main__.py` (3 lines)
**What it does:** Allows running `python -m suscheck`. Just calls `cli.app()`.
**Your idea:** ✅ Aligned.

### `src/suscheck/cli.py` (518 lines) — THE BRAIN
**What it does:** This is the main entry point. It defines two commands:
- `suscheck scan <target>` — runs the full pipeline described above
- `suscheck version` — shows version + which API keys are configured

It also contains the temporary PRI scoring function (will be replaced by a proper `risk_aggregator.py` in Increment 14).

**Your idea from Checkpoint 1a:** Your plan calls for 8 commands: `scan`, `explain`, `trust`, `install`, `clone`, `connect`, `init`, `version`. Currently only `scan` and `version` are implemented. The other 6 will be added in Increments 9 (`trust`), 15 (`install`/`clone`/`connect`), and 17 (`explain`).

---

### `src/suscheck/core/auto_detector.py` (379 lines)
**What it does:** When you give SusCheck a file, this module figures out WHAT it is. It uses three detection methods:
1. **Magic bytes** — reads the first few bytes of the file (e.g., `#!/bin/bash` means shell script, `MZ` means Windows EXE)
2. **File extension** — `.py` = Python, `.ps1` = PowerShell, etc.
3. **Content heuristics** — looks at the actual text to guess the language

It returns a `DetectionResult` with the artifact type, language, confidence score, and how it detected it.

**Your idea from Checkpoint 1a §6:** Your plan says "Five-layer identification: magic bytes → shebang → extension → content heuristics → **mismatch detection**." We have the first 4 layers but NOT mismatch detection (where extension says .txt but magic bytes say EXE — that itself should be a security finding). Also missing: polyglot file detection.

### `src/suscheck/core/finding.py` (117 lines)
**What it does:** Defines the universal vocabulary for the entire tool:
- `Finding` — a single security issue found (has: module, title, severity, confidence, line number, MITRE ATT&CK IDs, evidence dict, human review flag, AI explanation fields)
- `Severity` — CRITICAL / HIGH / MEDIUM / LOW / INFO
- `FindingType` — C2_COMMUNICATION, ENCODED_PAYLOAD, SECRET_EXPOSURE, DANGEROUS_FUNCTION, VULNERABILITY, etc.
- `Verdict` — CLEAR / CAUTION / HOLD / ABORT
- `ScanSummary` — the final report object with all findings, PRI score, verdict, timing, modules that ran

**Your idea from Checkpoint 1a §17:** ✅ This matches exactly. Every field from your spec (`module`, `finding_id`, `title`, `description`, `severity`, `finding_type`, `confidence`, `file_path`, `line_number`, `code_snippet`, `context`, `mitre_ids`, `evidence`, `needs_human_review`, `review_reason`, `ai_explanation`, `ai_false_positive`, `ai_confidence`) is implemented.

---

### `src/suscheck/tier0/hash_engine.py` (115 lines)
**What it does:** Computes SHA-256, MD5, and SHA-1 hashes of any file. It reads files in 64KB chunks so it doesn't crash on huge files (you could scan a 10GB ISO and it would work fine). Returns a `HashResult` dataclass with all three hashes.

**Your idea:** ✅ Fully aligned with Checkpoint 1a §7 Module 1 ("Compute SHA-256/MD5/SHA-1").

### `src/suscheck/tier0/virustotal.py` (477 lines) — BIGGEST FILE
**What it does:** Full VirusTotal API v3 client. It can:
1. **Look up a file hash** — "Has VT seen this SHA-256 before? How many engines flagged it?"
2. **Look up a URL** — "Is this URL known to be malicious?"
3. **Look up an IP address** — "Is this IP associated with malware?"
4. **Look up a domain** — "Is this domain suspicious?"
5. **Upload a file** — Sends the actual file to VT for sandbox analysis (only when user passes `--upload-vt` flag). Polls for results.

It handles rate limiting (429 responses), invalid keys (401/403), network errors, and timeouts gracefully. If no API key is set, it skips silently.

**Your idea:** ✅ Fully aligned. This is exactly what Checkpoint 1a §7 Module 1 and §9 Tool Orchestration Map say. The URL/IP/domain lookups are used for indicator enrichment in Tier 1.

### `src/suscheck/tier0/engine.py` (337 lines)
**What it does:** The Tier 0 orchestrator. It:
1. Calls `hash_engine` to compute hashes
2. Calls `virustotal` to look up the hash
3. Implements the **short-circuit rule**: if VT says 26+ engines flagged it → immediately ABORT the scan, don't even bother with Tier 1
4. If VT has never seen the hash → creates a "Needs Human Review" finding
5. Returns a `Tier0Result` with findings, VT data, timing, and whether to short-circuit

**Your idea:** ✅ Fully aligned with Checkpoint 1a §5 ("short-circuit ABORT if 26+ detections").

### `src/suscheck/tier0/abuseipdb.py` (157 lines) — NEW
**What it does:** Queries the AbuseIPDB API v2 to check if an IP address has been reported as malicious. When the Layer 1 code scanner extracts IP addresses from a file, this client checks each one against AbuseIPDB's database and returns an abuse confidence score (0-100%). It converts results into standard `Finding` objects with appropriate severity (80%+ = CRITICAL, 50%+ = HIGH, etc.).

**Your idea:** ✅ Aligned with Checkpoint 1a §9 ("URL/IP/Domain reputation: VirusTotal, AbuseIPDB, URLhaus"). URLhaus is not yet implemented.

---

### `src/suscheck/modules/code_scanner.py` (196 lines)
**What it does:** The Layer 1 orchestrator. It:
1. Checks if the file is too large (>5MB → skip)
2. Checks if it's binary (>10% non-text bytes → skip)
3. Reads the file content
4. Runs all 5 detectors (encoded_strings, network_indicators, entropy, credentials, dangerous_functions)
5. Deduplicates findings (same line + same module = one finding)
6. Handles errors per-detector (if one detector crashes, the others still run)

**Your idea:** ✅ This matches the "Universal Code Scanner" from Checkpoint 1a §7 Module 5. The structure is correct but is missing the recursive decoder (Increment 5) and the Layer 2 TOML plugin loader (Increment 6).

### `src/suscheck/modules/detectors/encoded_strings.py` (326 lines)
**What it does:** Hunts for hidden/encoded payloads in source code. It looks for:
- **Base64 strings** — decodes them and checks if the decoded content contains suspicious keywords (like "http", "eval", "shell", "/bin/sh")
- **Hex escape sequences** — `\x63\x75\x72\x6c` = "curl"
- **URL encoding** — `%63%75%72%6c` = "curl"
- **Unicode escapes** — `\u0065\u0076\u0061\u006c` = "eval"

When it finds and decodes something suspicious, it creates a HIGH severity finding.

**Your idea from Checkpoint 1a §7 Module 5 Layer 1:** Says "Encoded string detection (base64, hex, **XOR, rot13**, URL encoding, Unicode escapes)." We have base64, hex, URL, and Unicode. **Missing: XOR and rot13 decoders.** These would be part of the Recursive Decoder (Increment 5).

### `src/suscheck/modules/detectors/network_indicators.py` (344 lines)
**What it does:** Extracts every network indicator (IP, URL, domain) from file content and classifies them:
- **Paste sites** (pastebin.com, paste.ee, transfer.sh) → HIGH — data exfiltration
- **Dynamic DNS** (ngrok.io, serveo.net, localtunnel.me) → HIGH — tunneling
- **C2 infrastructure** (discord.com/api/webhooks, api.telegram.org/bot) → CRITICAL — command & control
- **Suspicious ports** (4444, 1337, 6667) → MEDIUM — reverse shell/IRC
- **External IPs** → LOW — interesting but not necessarily malicious
- Filters out version numbers that look like IPs (e.g., `version = "1.2.3.4"`)
- Filters out safe URLs (github.com, docs.python.org, pypi.org)

The hardcoded lists are just for **fast local triage**. Once extracted, the IPs and URLs are sent to the real APIs (VirusTotal and AbuseIPDB) in `cli.py` for live verification.

**Your idea:** ✅ Aligned with Checkpoint 1a §7 Module 5 Layer 1 ("IP/URL/domain extraction + reputation checking via VT, AbuseIPDB, URLhaus"). The extraction + fast classification is done here; the API enrichment happens in `cli.py`. **Missing: URLhaus integration.**

### `src/suscheck/modules/detectors/entropy.py` (246 lines)
**What it does:** Uses **Shannon entropy** (an information theory formula) to measure how random a string is. Why? Because:
- Normal English text has entropy ~4.0-4.5
- Normal code has entropy ~4.5-5.0
- **Encrypted payloads, obfuscated malware, or compressed viruses have entropy ~5.5-6.5+**

It scans every line, extracts quoted strings and long tokens, computes their entropy, and flags anything above the threshold. It's smart enough to filter out:
- UUIDs (high entropy but harmless)
- Known hash formats (SHA-256 hashes are high entropy but expected)
- Short strings (not enough data for meaningful entropy)

**Your idea:** ✅ Fully aligned with Checkpoint 1a §7 Module 5 Layer 1 ("High-entropy string detection (Shannon entropy)").

### `src/suscheck/modules/detectors/credentials.py` (298 lines)
**What it does:** Regex-based detection for 14+ types of hardcoded secrets:
- AWS Access Key ID (`AKIA...`)
- AWS Secret Access Key
- GitHub Personal Access Token (`ghp_...`)
- Stripe API Key (`sk_live_...`)
- Google API Key (`AIzaSy...`)
- Slack Bot Token (`xoxb-...`)
- Private Keys (RSA/DSA/EC `-----BEGIN ... PRIVATE KEY-----`)
- Generic passwords (`password = "..."`)
- Generic secrets (`secret_key = "..."`)
- Auth tokens
- Database connection strings with embedded credentials

It has **false positive filtering** — it ignores:
- Empty strings (`password = ""`)
- Placeholder values (`"REPLACE_ME"`, `"changeme"`, `"your_password_here"`)
- Environment variable references (`os.environ.get("SECRET_KEY")`)

**Your idea:** ✅ Aligned with Checkpoint 1a §7 Module 5 Layer 1 ("Embedded credential patterns"). The checkpoint also mentions **gitleaks** for secret scanning in the repo scanner (Increment 10) — that would be a separate, more thorough secret scanner that also checks git history.

### `src/suscheck/modules/detectors/dangerous_functions.py` (479 lines)
**What it does:** Detects code that tries to execute OS commands, bypass security, or establish persistence. It has 35+ patterns across 8 languages:

**Python:** `eval()`, `exec()`, `os.system()`, `subprocess.call()`, `__import__()`, `pickle.loads()`
**JavaScript:** `eval()`, `eval(atob())`, `Function()`, `setTimeout(string)`, `document.write()`
**PowerShell:** `Invoke-Expression`/`IEX`, `New-Object Net.WebClient`, `-EncodedCommand`, `AMSI bypass`
**Bash/Shell:** `curl | bash`, `wget | sh`, `nc -e /bin/sh` (reverse shell), cron persistence
**Batch/CMD:** PowerShell from batch, `reg add`, UAC bypass
**PHP:** `system()`, `passthru()`, `base64_decode()`, `preg_replace /e`
**Java:** `Runtime.exec()`, `ProcessBuilder`
**General:** `chmod 777`, download-and-execute patterns

Each pattern has a severity, confidence score, MITRE ATT&CK ID, and description.

**Your idea:** ✅ Fully aligned with Checkpoint 1a §7 Module 5 Layer 2 language-specific patterns. The checkpoint says these should eventually live in TOML plugin files (Increment 6), but for now they're hardcoded in Python. The TOML system will let the community add more rules without writing Python code.

---

### `src/suscheck/modules/semgrep_runner.py` (153 lines)
**What it does:** Orchestrates the external **Semgrep** binary (if installed) to catch vulnerability patterns that our regex-based detectors can't:
- SQL Injection
- Command injection via subprocess
- XSS
- Path traversal
- Insecure deserialization
- And hundreds of other community-maintained rules

It runs `semgrep scan --json --quiet --config auto <file>`, parses the JSON output, and converts each Semgrep finding into our standard `Finding` dataclass. If Semgrep isn't installed, it skips gracefully.

**Your idea:** ✅ Aligned with Checkpoint 1a §9 Tool Orchestration Map ("SAST vulnerability patterns → Semgrep"). The checkpoint also mentions **Bandit** as a Python-specific fallback — that's not implemented yet.

---

### `src/suscheck/output/terminal.py` (217 lines)
**What it does:** The pretty-printer. Uses the Rich library to render:
- Detection result tables (artifact type, language, confidence)
- Hash tables (SHA-256, MD5, SHA-1)
- Finding lists with severity badges (🚫 CRITICAL, 🔶 HIGH, ⚠️ MEDIUM, ℹ️ INFO)
- "Needs Human Review" panels
- Score Explanation panel (showing how each finding contributes to the PRI score)
- Verdict panel with progress bar (CLEAR ✅ / CAUTION ⚠️ / HOLD 🔶 / ABORT 🚫)
- Scan footer (timing, modules ran, modules skipped)

**Your idea:** ✅ Aligned with Checkpoint 1a §13 ("Terminal (Rich) — default"). Missing: `json_output.py` (`--output json`), `html_report.py` (`--report html`), `markdown_report.py` (`--report md`) — all planned for Increment 16.

---

## Alignment Summary

| Your Idea (Checkpoint 1a) | Aligned? | Notes |
|---------------------------|----------|-------|
| Pre-execution scanning philosophy | ✅ Yes | Core of the tool |
| Multi-tier pipeline (Tier 0 → Tier 1 → Tier 2 → PRI) | ✅ Yes | Working |
| No hallucinations, real API calls | ✅ Yes | VT and AbuseIPDB use real keys |
| Graceful degradation (missing key = skip) | ✅ Yes | Implemented everywhere |
| AutoDetection (magic bytes) | ✅ Yes | Missing polyglot/mismatch |
| Hash + VirusTotal (Tier 0) | ✅ Yes | Complete including upload |
| Short-circuit on confirmed malware | ✅ Yes | 26+ detections → ABORT |
| Layer 1 detectors (5 modules) | ✅ Yes | All 5 working |
| Recursive decoder | ❌ No | Increment 5, not started |
| TOML language plugin system | ❌ No | Increment 6, not started |
| Full 10-step PRI scoring | ⚠️ Partial | Only steps 1-2 implemented |
| Config/IaC scanner (KICS) | ❌ No | Increment 8, not started |
| Supply chain trust (9 categories) | ❌ No | Increment 9, not started |
| Repository scanner (gitleaks) | ❌ No | Increment 10, not started |
| MCP scanner (your biggest differentiator!) | ❌ No | Increment 11-12, not started |
| AI triage (multi-model) | ❌ No | Increment 13, not started |
| Wrapper modes (install/clone/connect) | ❌ No | Increment 15, not started |
| Report generation (HTML/MD) | ❌ No | Increment 16, not started |
| Explain mode | ❌ No | Increment 17, not started |
| REVIEW flag for uncertainty | ✅ Yes | `needs_human_review` field works |
| Semgrep orchestration | ✅ Yes | Ahead of schedule (was Inc 8) |
| AbuseIPDB integration | ✅ Yes | Not in original plan but valuable |
