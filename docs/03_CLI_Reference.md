# CLI reference

Entry point: `suscheck` (Typer). Loads `.env` from the project root (next to `pyproject.toml`) and the current working directory via `python-dotenv`.

## `suscheck scan <target>`

Runs detection, then as much of the pipeline as applies to the target.

### Local file

1. **Auto-detection** table printed (artifact type, language, path, mismatch / polyglot).
2. **Tier 0:** Hash + VirusTotal (if `SUSCHECK_VT_KEY` set). Optional `--upload-vt` uploads the file to VT (public).
3. **Short-circuit:** If Tier 0 decides the file is known-malicious, scanning stops and PRI is finalized early.
4. **Tier 1:** Chooses **MCP → config → code** scanner (`MCPScanner` runs first when the path/name/content indicates MCP JSON).
5. **Enrichment:** For **code** scan results, a subset of extracted URLs/IPs may be checked against VT / AbuseIPDB (rate-limited in code).
6. **Tier 2:** **Semgrep** if the binary is on `PATH`.
7. **PRI** via `RiskAggregator` and Rich output.

### Directory

If the path is a directory **with** `.git`, it is treated as a **repository**; Tier 1 uses **gitleaks** (requires `gitleaks` installed). Tier 0 is not run on directories in the current implementation (message explains skip).

### Non-file targets (URL, package name)

Detection returns URL or package assumptions; **Tier 0** and file-based Tier 1 are skipped. PRI still summarizes whatever findings exist (often none without further modules).

### Flags (check behavior in `cli.py`)

| Flag | Declared purpose | Actually wired in code? |
|------|------------------|-------------------------|
| `--output` / `-o` | terminal vs json | **Not implemented** — scan always uses terminal rendering today. |
| `--report` / `-r` | html, markdown | **Not implemented** — no report files written. |
| `--upload-vt` | upload unknown file to VT | **Yes** |
| `--mcp-dynamic` | after a static MCP JSON scan, run Docker observation (stdio servers only) | **Yes** — requires `docker` Python package + local Docker daemon; see `mcp_dynamic.py` |
| `--no-ai` | skip AI triage | **Yes** — when unset, `scan` may call configured LLM after Tier 2 (needs `SUSCHECK_AI_*` env). |
| `-v` / `--verbose` | logging | **Yes** |

Use `suscheck scan -h` for the full Typer-generated help.

---

## `suscheck trust <package>`

Supply-chain–focused check via `TrustEngine`: PyPI metadata, typosquatting vs a small popular-package set, yanked/abandonment-style signals, and deps.dev–backed transitive risk as wired in code.

**Ecosystem:** The CLI accepts `--ecosystem` / `-e`, but **`trust_engine.py` only implements `pypi` today** — any other value returns a clear “not supported” error from the engine.

---

## `suscheck version`

Prints version, Python version, configured API key **presence** (partial prefixes only), and whether external tools (`gitleaks`, `semgrep`, `bandit`, `docker`, `kics`) exist on `PATH`.

---

## `suscheck install <ecosystem> <package>`

Safety wrapper around `pip`/`npm` style installs.

- **Flow:** runs a full `scan` against the package identifier (e.g. `pypi:requests`), including Tier 0/1/2, TrustEngine, and PRI scoring.
- **Threshold:** if `PRI > 40` (HOLD/ABORT band) the command prints a red “Install Blocked” panel and **does not** run the underlying installer.
- **Force override:** `--force` bypasses the block and runs the installer anyway, with an explicit warning.
- **Ecosystems:**
  - `pip` / `pypi` → executes `python -m pip install <package>`
  - `npm` → executes `npm install <package>`

Findings and the Score Explanation panel come from the regular `scan` pipeline; no separate logic is used for wrapper mode.

## `suscheck clone <url>`

Safety wrapper around `git clone` for repositories.

- **Flow:** runs `scan <url>` first; URL auto-detection treats common Git hosts as `repository` artifacts.
- **Threshold:** if `PRI > 15` (anything other than CLEAR) the clone is **blocked** with a red “Clone Blocked” panel.
- **Force override:** `--force` allows the `git clone` to proceed even when the score is CAUTION/HOLD/ABORT.
- **Destination:** optional `--dest / -d` argument is passed as the final `git clone` parameter.

## `suscheck connect <server>`

Safety gate for MCP servers before wiring them into a client.

- **Flow:** runs `scan <server>` (URL or manifest path). Static MCP rules apply when the target is a JSON manifest.
- **Threshold:** mirrors the repository policy — if `PRI > 15`, connection is **blocked** by default.
- **Force override:** `--force` records an explicit warning but allows the user to proceed manually.
- **NOTE:** `suscheck connect` does **not** modify editor/client configs or open network connections itself; it only decides whether the MCP target is “allowed” from a PRI standpoint and reports the results.

`suscheck explain <file>` remains a placeholder for Increment 17.

---

## Environment variables (common)

Documented in `.env.example` in the repo. Typical names include `SUSCHECK_VT_KEY`, `SUSCHECK_ABUSEIPDB_KEY`, `SUSCHECK_GITHUB_TOKEN`, `SUSCHECK_NVD_KEY`, AI-related vars. **Missing keys:** corresponding features skip; the tool should not crash.
