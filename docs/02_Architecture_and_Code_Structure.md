# Architecture & Code Structure

SusCheck is a **multi-layered security analysis platform** built on a pluggable pipeline architecture. Every stage produces standardized `Finding` objects, which are then aggregated by the **`RiskAggregator`** to produce a final Probability-Risk Index (**PRI**) score.

## End-to-end flow (`suscheck scan <path>`)

The scanning pipeline follows a "Tiered Defense" model:

```
┌─────────────────┐     ┌──────────────┐     ┌─────────────────────────────────────────┐
│  Auto-detector  │ ──► │   Tier 0     │ ──► │  Tier 1: Static module orchestration    │
│  (Type/Lang)    │     │ Rep + Hash   │     │  (MCP, Repo, Config, Code, Web)          │
└─────────────────┘     └──────────────┘     └─────────────────────────────────────────┘
        │                        │                              │
        │                        │ short-circuit (known bad)    │
        ▼                        ▼                              ▼
   mismatch /              stop early                   External Reputation 
   polyglot findings                                    (VT, AbuseIPDB, NVD) 
                                                                   │
                                                                   ▼
                        ┌─────────────────┐     ┌────────────────────────────┐
                        │  Tier 2         │     │  Triage & Risk Aggregation │
                        │  External tools │     │  (PRI + AI Explanation)    │
                        │  (Semgrep, etc) │     └────────────────────────────┘
                        └─────────────────┘
```

### 1. Auto-detector (`core/auto_detector.py`)
- **IDENTIFICATION**: Uses magic bytes (libmagic), shebangs, extensions, and content heuristics.
- **SUPPORTED**: 40+ languages/formats, including **Python, JavaScript, PHP, HTML, Bash, PowerShell, C/C++, Docker, Terraform,** and more.
- **SECURITY FINDINGS**: Automatically flags **extension vs magic byte mismatches** and identifies **polyglot** files.

### 2. Tier 0 Analysis (`modules/external/`)
- **REPUTATION**: Queries VirusTotal and AbuseIPDB using file hashes and network indicators.
- **SHORT-CIRCUIT**: If a file is decisively malicious on VirusTotal, the scan can stop early to protect resources.

### 3. Tier 1 Static Modules (`modules/`)
SusCheck picks the most specific scanner for the target:
- **MCPScanner**: Specialized for Model Context Protocol servers (risky commands, prompt injections).
- **RepoScanner**: Repository-level audit (Gitleaks for secrets, contributor anomalies).
- **ConfigScanner**: Infrastructure-as-Code (KICS for Docker/K8s/Terraform).
- **CodeScanner**: Deep-dive analysis for **HTML, PHP, Scripts,** and general code.
    - **Layer 1**: Entropy (packer detection), decoded strings (obfuscation), network detectors.
    - **Layer 2**: Targeted TOML plugins (e.g., `web_shells.toml`, `phishing.toml`).

### 4. Risk Triage (`core/risk_aggregator.py`)
- **PRI SCORE**: A 0–100 score calculated by weighting severity, confidence, and context (e.g., install scripts have higher risk).
- **AI ENRICHMENT**: Findings are optionally refined by AI to provide human-readable risk explanations and eliminate false positives.

---


## Repository root (`rules/`)

TOML/JSON rules and mappings used at runtime: language plugins, `network.toml`, `mcp.toml`, `mitre_mapping.json`. See [05_Rules_Reference.md](05_Rules_Reference.md).

## Tests (`tests/`)

Mirror major areas: `test_tier0`, `test_core`, `test_code_scanner`, `test_repo`, `test_mcp`, etc. **Malicious samples** for manual runs live under `tests/samples/` (when present); automated tests prefer **temp files** and mocks.

## Checkpoint 1a alignment

The roadmap in `Checkpoints/Checkpoint 1a.MD` describes the **full** product vision. **Implementation status** is tracked honestly in `Checkpoints/Progress_Audit.md` (increments done vs still open). This architecture doc describes **what the code does today**.
