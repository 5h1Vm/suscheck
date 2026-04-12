# Architecture & code structure

SusCheck is a **CLI-first** pipeline: each stage produces `Finding` objects; **`RiskAggregator`** turns them into a **PRI** score and verdict; **`terminal`** (Rich) renders output.

## End-to-end flow (`suscheck scan <path>`)

Applies when the target resolves to a **local file** (directories and non-file targets follow different branches).

```
┌─────────────────┐     ┌──────────────┐     ┌─────────────────────────────────────────┐
│  Auto-detector  │ ──► │   Tier 0     │ ──► │  Tier 1: one primary static module      │
│  artifact type  │     │ hash + VT    │     │  MCP → repo → config → code (first match)│
└─────────────────┘     └──────────────┘     └─────────────────────────────────────────┘
        │                        │                              │
        │                        │ short-circuit (known bad)    │
        ▼                        ▼                              ▼
   mismatch /              stop early                   optional VT/AbuseIPDB
   polyglot findings                                    enrichment on code URLs/IPs
                                                                  │
                                                                  ▼
                        ┌─────────────────┐     ┌────────────────────────────┐
                        │  Tier 2         │     │  RiskAggregator (PRI)      │
                        │  Semgrep        │     │  + terminal output         │
                        │  (if installed) │     └────────────────────────────┘
                        └─────────────────┘
```

### Auto-detector (`core/auto_detector.py`)

**What:** Chooses `ArtifactType` (code, config, repository, package, mcp_server, binary, unknown) and `Language` (python, json, dockerfile, **mcp_manifest**, …).

**Why:** Downstream scanners use this to pick tools and to apply PRI **context multipliers** (e.g. MCP).

**Notable behavior:** Filename rules (`Dockerfile`, `mcp.json`, …), magic bytes (via `python-magic` when installed), shebang, extension, content heuristics, **extension vs magic mismatch** (security finding), **polyglot** flag, and **MCP JSON** heuristics (`mcpServers` marker in `.json` files).

### Tier 0 (`tier0/`)

**What:** `Tier0Engine` hashes the file (`hash_engine.py`), queries VirusTotal (`virustotal.py`), and may **short-circuit** the scan when reputation is decisively bad.

**Why:** Fast, shared ground truth before expensive static rules.

### Tier 1 static modules (`modules/`)

For a **single file**, `cli.py` picks **one** primary scanner (first `can_handle` match):

| Order | Module | Rough role |
|-------|--------|------------|
| 1 | `MCPScanner` (`mcp_scanner.py`) | MCP client/manifest JSON: `mcpServers`, risky commands, tool names, prompt patterns (`rules/mcp.toml`) |
| 2 | `RepoScanner` (`repo_scanner.py`) | **Directories only** — not used for single files in this branch |
| 3 | `ConfigScanner` (`config_scanner.py`) | Dockerfile / YAML / JSON configs, KICS + custom CI rules |
| 4 | `CodeScanner` (`code_scanner.py`) | Layer 1 detectors + recursive decode peel + TOML plugins |

**Why this order:** MCP-shaped JSON must run **before** the generic config scanner, which would otherwise treat any `.json` as generic IaC/config.

For a **directory** with `.git`, auto-detection yields **repository**; `scan` uses **gitleaks** via `RepoScanner`. Tier 0 is skipped for non-files.

### Tier 2 (Semgrep)

**What:** `semgrep_runner.py` runs the external `semgrep` CLI when present.

**Why:** Community vulnerability rules (SQLi, unsafe `subprocess`, etc.) complement regex/threat heuristics.

### PRI (`core/risk_aggregator.py`)

**What:** Combines severities, confidence, **context multiplier** (install script / package / **MCP**), **correlation bonuses**, **VirusTotal** adjustments, clamp 0–100, verdict bands.

**Why:** One explainable score. *Note:* The `trust` command’s trust score is **separate** from PRI today; `RiskAggregator` still uses a **1.0×** placeholder for “supply chain trust multiplier” inside `scan` (see developer guide).

### Output (`output/terminal.py`)

**What:** Rich tables, panels, finding lists, PRI breakdown.

**Why:** Human-readable default. JSON/HTML/Markdown report paths are **not** implemented in code yet (flags may exist on `scan` without full wiring—see CLI reference).

---

## Directory layout (`src/suscheck/`)

```
src/suscheck/
├── __init__.py          # package version
├── __main__.py          # python -m suscheck → cli
├── cli.py               # Typer commands, scan orchestration
├── core/
│   ├── auto_detector.py # artifact / language detection
│   ├── finding.py       # Finding, enums, ScanSummary
│   └── risk_aggregator.py
├── tier0/
│   ├── engine.py        # Tier0 orchestrator
│   ├── hash_engine.py
│   ├── virustotal.py
│   └── abuseipdb.py
├── modules/
│   ├── base.py          # ScannerModule, ModuleResult
│   ├── code_scanner.py
│   ├── recursive_decoder.py
│   ├── mcp_scanner.py
│   ├── config_scanner.py
│   ├── repo_scanner.py
│   ├── semgrep_runner.py
│   ├── config/
│   │   └── kics_orchestrator.py
│   ├── repo/
│   │   └── gitleaks_runner.py
│   ├── supply_chain/
│   │   ├── trust_engine.py
│   │   ├── pypi_client.py
│   │   └── depsdev_client.py
│   └── detectors/
│       ├── plugin_loader.py
│       ├── encoded_strings.py
│       ├── network_indicators.py
│       ├── entropy.py
│       └── credentials.py
└── output/
    └── terminal.py
```

## Repository root (`rules/`)

TOML/JSON rules and mappings used at runtime: language plugins, `network.toml`, `mcp.toml`, `mitre_mapping.json`. See [05_Rules_Reference.md](05_Rules_Reference.md).

## Tests (`tests/`)

Mirror major areas: `test_tier0`, `test_core`, `test_code_scanner`, `test_repo`, `test_mcp`, etc. **Malicious samples** for manual runs live under `tests/samples/` (when present); automated tests prefer **temp files** and mocks.

## Checkpoint 1a alignment

The roadmap in `Checkpoints/Checkpoint 1a.MD` describes the **full** product vision. **Implementation status** is tracked honestly in `Checkpoints/Progress_Audit.md` (increments done vs still open). This architecture doc describes **what the code does today**.
