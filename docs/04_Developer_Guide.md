# Developer guide — what each file does (and why)

This document describes **the current SusCheck codebase** under `src/suscheck/` and related roots. Line counts are approximate (`wc -l`, April 2026). If the code changes, update this file or treat counts as non-authoritative.

For the product roadmap vs implementation gap list, use **`Checkpoints/Progress_Audit.md`**. For rule file formats, see **[05_Rules_Reference.md](05_Rules_Reference.md)**.

---

## How `suscheck scan` uses these pieces

1. **`cli.py`** — orchestrates detection, Tier 0, Tier 1 module selection, optional VT/Abuse enrichment, Semgrep, PRI, output.
2. **`auto_detector.py`** — classifies the target; emits mismatch/polyglot **findings** before Tier 0.
3. **`tier0/engine.py`** — hashes + VT; may short-circuit.
4. **Tier 1** — `mcp_scanner` OR `config_scanner` OR `code_scanner` (and **directories** → `repo_scanner` / gitleaks).
5. **`risk_aggregator.py`** — PRI from collected findings + VT snapshot.
6. **`terminal.py`** — Rich UI.

---

## Package entry

### `src/suscheck/__init__.py` (~4 lines)

**What:** Exposes `__version__`.

**Why:** Single source for `suscheck version` and packaging.

### `src/suscheck/__main__.py` (~5 lines)

**What:** Invokes the Typer app when you run `python -m suscheck`.

**Why:** Standard Python package entry for development.

---

## CLI

### `src/suscheck/cli.py` (~550 lines)

**What:** Typer application: `scan`, `explain` (stub), `trust`, `install`/`clone`/`connect` (stubs), `version`. Loads dotenv, runs the pipeline described in [02_Architecture_and_Code_Structure.md](02_Architecture_and_Code_Structure.md).

**Why:** Single user-facing command surface.

**Honest notes:**

- `RiskAggregator` is used for PRI (not an inline copy in this file).
- `--output json` and `--report` are **declared** but **not** fully implemented for scan output at the time of writing—see [03_CLI_Reference.md](03_CLI_Reference.md).

---

## Core models & detection

### `src/suscheck/core/finding.py` (~113 lines)

**What:** `Finding`, `Severity`, `FindingType`, `Verdict`, `ScanSummary` — the shared contract for every module.

**Why:** One schema for terminal output, tests, and future JSON/SARIF exporters.

### `src/suscheck/core/auto_detector.py` (~394 lines)

**What:** `AutoDetector.detect()` → `DetectionResult` with `ArtifactType`, `Language`, confidence, polyglot, extension/magic **mismatch** findings, special filenames (Docker, MCP manifests), and JSON content sniffing for `"mcpServers"`.

**Why:** Downstream scanners and PRI context depend on accurate classification.

### `src/suscheck/core/risk_aggregator.py` (~170 lines)

**What:** `RiskAggregator.calculate()` → `PRIScore`: base points × confidence, **context multiplier** (script / package / **MCP**), correlation bonuses (obfuscation + network/execution, etc.), **VirusTotal** adjustment bands, clamp, verdict.

**Why:** Explainable single score.

**Honest notes:**

- Docstring references a “10-step” algorithm; several steps are **partially** implemented (e.g. supply-chain trust multiplier inside `scan` is still **1.0×**; the `trust` command’s score does **not** feed into this path automatically).
- Step 7 AI adjustment is **not** implemented.

---

## Tier 0

### `src/suscheck/tier0/__init__.py`

**What:** Re-exports `Tier0Engine`, `HashEngine`, `VirusTotalClient`, etc.

**Why:** Clean `from suscheck.tier0 import Tier0Engine`.

### `src/suscheck/tier0/hash_engine.py` (~115 lines)

**What:** Streaming SHA-256, MD5, SHA-1 for local files.

**Why:** VT and display; handles large files without loading entirely into RAM.

### `src/suscheck/tier0/virustotal.py` (~477 lines)

**What:** VirusTotal API v3 client: file hash lookup, URL/IP/domain lookups, optional upload + polling.

**Why:** External reputation for files and extracted indicators.

### `src/suscheck/tier0/engine.py` (~337 lines)

**What:** Orchestrates hashing + VT, builds Tier 0 **findings**, **short-circuit** when detections exceed the configured threshold.

**Why:** Fast abort on known bad content.

### `src/suscheck/tier0/abuseipdb.py` (~157 lines)

**What:** AbuseIPDB client; maps high abuse scores to `Finding`s.

**Why:** IP reputation for indicators extracted in Tier 1 (invoked from `cli.py`, not inside individual detectors).

---

## Scanner module infrastructure

### `src/suscheck/modules/base.py` (~74 lines)

**What:** `ModuleResult` dataclass and `ScannerModule` ABC (`name`, `can_handle`, `scan`).

**Why:** Uniform return type for config / repo / MCP / supply chain modules.

---

## Tier 1 — code path

### `src/suscheck/modules/code_scanner.py` (~206 lines)

**What:** Validates size/binary, reads text, runs `RecursiveDecoderEngine` to append peeled payloads to the buffer, then runs detectors: encoded strings, network, entropy, credentials, **TOML plugin_loader**. Deduplicates findings.

**Why:** Main “universal” static analysis for source-like files.

### `src/suscheck/modules/recursive_decoder.py` (~76 lines)

**What:** Multi-layer decoding (e.g. nested base64/hex/url) up to a bounded depth; surfaces decoded text for downstream regex detectors.

**Why:** Many real payloads hide behind multiple encodings.

### `src/suscheck/modules/detectors/encoded_strings.py` (~405 lines)

**What:** Base64, hex, URL encoding, Unicode escapes, **rot13** usage, **XOR** pattern detection, and related findings.

**Why:** Obfuscation and staging in pre-execution artifacts.

### `src/suscheck/modules/detectors/network_indicators.py` (~349 lines)

**What:** IPs, URLs, domains; classifies paste sites, dynamic DNS, C2-ish endpoints; loads extra patterns from **`rules/network.toml`** when present.

**Why:** Network IOC extraction for local triage + optional VT/Abuse follow-up in `cli.py`.

### `src/suscheck/modules/detectors/entropy.py` (~246 lines)

**What:** Shannon entropy on strings/tokens; filters UUIDs and known hash-like tokens.

**Why:** Highlights possibly encrypted or compressed blobs.

### `src/suscheck/modules/detectors/credentials.py` (~298 lines)

**What:** Regexes for common secret formats (AWS, GitHub PAT, Stripe, private keys, etc.) with placeholder / env-reference filtering.

**Why:** Hardcoded credential leakage before execution.

### `src/suscheck/modules/detectors/plugin_loader.py` (~141 lines)

**What:** Loads `rules/universal.toml` and `rules/{language}.toml`, compiles `[[rules]]` regexes, emits `Finding`s per line.

**Why:** Layer 2 threat rules without shipping Python per pattern.

---

## Tier 1 — config / IaC

### `src/suscheck/modules/config_scanner.py` (~119 lines)

**What:** Custom regex (e.g. `curl|bash`-style CI/Docker risks) + **`KicsOrchestrator`**.

**Why:** DevOps misconfig and lateral movement patterns.

### `src/suscheck/modules/config/kics_orchestrator.py` (~116 lines)

**What:** Runs **KICS** via subprocess when the binary exists; parses output into `Finding`s.

**Why:** Broad IaC rule coverage without reimplementing Checkmarx rules in Python.

---

## Tier 1 — repository secrets

### `src/suscheck/modules/repo_scanner.py` (~59 lines)

**What:** For **directories**, runs **`GitleaksRunner`**.

**Why:** Secret scanning across trees / git history (when gitleaks is installed).

### `src/suscheck/modules/repo/gitleaks_runner.py` (~116 lines)

**What:** Subprocess orchestration and JSON report parsing for gitleaks.

**Why:** Isolate CLI parsing from `RepoScanner` policy.

---

## Tier 1 — MCP static (Increment 11)

### `src/suscheck/modules/mcp_scanner.py` (~372 lines)

**What:** Parses MCP client JSON; analyzes `mcpServers` entries (command, args, url); collects tool names; matches **`rules/mcp.toml`** (`restricted_tools`, `prompt_rules`).

**Why:** Static assessment of agent-exposed capabilities before connecting an MCP server.

### `src/suscheck/modules/mcp_dynamic.py` (~320 lines)

**What:** `MCPDynamicScanner` + `observe_stdio_server_in_docker()`: uses Docker Engine API (`docker` PyPI extra) to run each **stdio** MCP `command` + `args` inside an inferred image (`node:20-bookworm-slim` vs `python:3.12-slim`). Observes ~60s (configurable via `observe_seconds` in `scan()` config), compares container network TX bytes, scans logs for `http(s)` URLs, emits INFO if process keeps running. **Skips** entries that only have `url` (remote transport).

**Why:** Increment 12 — lightweight dynamic signal without claiming full filesystem syscall tracing.

**Honest limits:** Pull/install traffic (e.g. `npx`) can raise TX; no destination-level capture without extra tooling; arbitrary commands may fail if the image lacks dependencies.

---

## Tier 1 — supply chain (trust command)

### `src/suscheck/modules/supply_chain/trust_engine.py` (~154 lines)

**What:** Implements `ScannerModule.scan()` for targets like `pypi:requests`. **Only PyPI** is implemented; other ecosystems error out. Combines PyPI signals with **deps.dev** data (as coded) into a 0–10 score and findings.

**Why:** Dedicated `suscheck trust` UX separate from file `scan`.

### `src/suscheck/modules/supply_chain/pypi_client.py` (~80 lines)

**What:** PyPI JSON API client.

**Why:** Package metadata for trust signals.

### `src/suscheck/modules/supply_chain/depsdev_client.py` (~88 lines)

**What:** deps.dev API client for dependency / advisory context.

**Why:** Transitive visibility without local installs.

---

## Tier 2 — Semgrep

### `src/suscheck/modules/semgrep_runner.py` (~153 lines)

**What:** Runs `semgrep` with JSON output; maps results to `Finding`.

**Why:** Vulnerability-style rules beyond regex threat hunting.

---

## AI triage (Increment 13)

### `src/suscheck/ai/key_resolution.py`

**What:** `api_key_for_provider()` returns `SUSCHECK_AI_KEY` if set, else common upstream names (`GROQ_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `OPENROUTER_API_KEY`, `MISTRAL_API_KEY`, `CEREBRAS_API_KEY`, `SAMBANOVA_API_KEY`, `OPENAI_API_KEY`, `GOOGLE_API_KEY`).

**Why:** Match how other tools and `.env` templates name keys without duplicating secrets.

### `src/suscheck/ai/http_retry.py`

**What:** `post_json_with_retry` — retries POST on **429** / **503** with `Retry-After` or exponential backoff (capped).

**Why:** Free-tier and shared keys hit rate limits; avoids failing a whole scan on transient throttling.

### `src/suscheck/ai/factory.py`

**What:** Maps `SUSCHECK_AI_PROVIDER` to implementations: **openai, groq, openrouter, mistral, cerebras, sambanova** → `OpenAICompatProvider` + default base URLs; **anthropic**; **gemini** / **google** → `GeminiProvider`; **ollama**; **none**.

**Why:** One entry point for `run_ai_triage`. Optional `SUSCHECK_AI_JSON_MODE=0` disables `response_format` for picky gateways; OpenRouter can use `OPENROUTER_HTTP_REFERER` / `OPENROUTER_APP_TITLE`.

### `src/suscheck/ai/triage_engine.py`

**What:** Serializes up to 24 findings (by severity), calls the provider for **one** JSON response (`pri_adjustment` in **[-15, 15]**, per-finding `explanation`, `likely_false_positive`, `confidence`), mutates `Finding.ai_*` fields, returns adjustment for PRI.

**Why:** Checkpoint 1a step 7 (AI ±15) + explain/FP hints without hardcoded verdicts.

### `src/suscheck/ai/providers/*`

**What:** `NoneProvider`; `OpenAICompatProvider` (OpenAI + Groq + custom base URL); `AnthropicProvider` (HTTP Messages API); `OllamaProvider` (`/api/chat`, `format: json`).

**Why:** Multi-backend support without requiring every SDK; **`google`** is explicitly not implemented yet (factory logs and falls back to none).

### `src/suscheck/ai/json_extract.py`

**What:** Strips markdown fences and `json.loads` model output.

---

## Output

### `src/suscheck/output/terminal.py` (~217 lines)

**What:** Rich rendering for headers, detection tables, VT summary, findings, PRI breakdown, verdict.

**Why:** Default human-readable report.

---

## Empty `__init__.py` packages

`modules/config/__init__.py`, `modules/repo/__init__.py`, `modules/supply_chain/__init__.py` — namespace markers only.

---

## Maintenance

When you add or rename modules:

1. Update this file and [02_Architecture_and_Code_Structure.md](02_Architecture_and_Code_Structure.md).
2. Update [03_CLI_Reference.md](03_CLI_Reference.md) if user-visible behavior changes.
3. Update `Checkpoints/Progress_Audit.md` for roadmap honesty.
4. Add tests under `tests/` mirroring the feature; keep malicious fixtures out of production paths.
