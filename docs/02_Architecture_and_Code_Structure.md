# Architecture & Code Structure

SusCheck uses a heavily decoupled pipeline model where findings from each engine are compiled sequentially.

## The Scanning Pipeline

```
Input File → Auto-Detector → Tier 0 (Hash/VT) → Tier 1 (Static Analysis / Code Scanner) → PRI Aggregator → Verdict Output
```

1. **Auto-Detector** (`suscheck.core.auto_detector`): Quickly evaluates magic bytes, shebang lines, and file extensions to categorize the artifact type (e.g., Python code, Shell script, binary).
2. **Tier 0** (`suscheck.tier0`): Calculates cryptographic hashes and passes them to VirusTotal. It contains a short-circuit rule to instantly abort scanning if malware is confirmed via external APIs.
3. **Tier 1** (`suscheck.modules.code_scanner`): The Layer 1 Code Scanner orchestrates all Language-Agnostic analyzers across files. Analyzers include:
   - **Credentials** (API keys, Tokens)
   - **Encoded Strings** (Base64, Hex payloads)
   - **Entropy Checks** (Randomized, potentially obfuscated logic)
   - **Dangerous Functions** (eval, exec, `curl|bash`, PowerShell IEX)
   - **Network Indicators** (Suspicious Domains, C2 Servers, Dynamic DNS)

---

## Directory Structure

Here's an overview of the important files currently implemented in `src/suscheck/`:

```
src/suscheck/
├── cli.py             # Main entry point using Typer. Handles configurations, flags, output.
├── core/              # Shared data definitions and utility structures
│   ├── auto_detector.py # Infers file types dynamically
│   └── finding.py       # Dataclass formats for Security Findings and Verdict statuses
├── modules/           # Tier 1 scanners (Static Analysis)
│   ├── code_scanner.py         # Main orchestrator for Tier 1 detectors
│   └── detectors/              # Individual analysis modules
│       ├── credentials.py          # Finds AWS, Stripe, GitHub PAT tokens etc.
│       ├── dangerous_functions.py  # Language-agnostic detection for execution/shells
│       ├── encoded_strings.py      # Extracts & decodes hidden payloads
│       ├── entropy.py              # Shannon Entropy measurement for strings
│       └── network_indicators.py   # Extracts Domains, IP, known Bad infra / Ports
├── output/            # Renders results back to the user
│   └── terminal.py      # Rich terminal rendering (Tables, Progress bars, Explanations)
└── tier0/             # Hash validation & VT Lookups
    ├── engine.py        # Orchestrator for Tier0 flow
    ├── hash_engine.py   # Local SHA256/MD5/SHA1 generation
    └── virustotal.py    # VirusTotal API interactions and polling logic for uploads
```
