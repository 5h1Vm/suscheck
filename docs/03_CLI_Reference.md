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
| `--no-ai` | skip AI triage | Placeholder for future use (no AI triage in pipeline yet). |
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

## Stub commands (placeholders)

These exist so the CLI surface matches the roadmap; they print a “coming in Increment …” style message:

- `suscheck explain <file>` — Increment 17
- `suscheck install …` — Increment 15
- `suscheck clone …` — Increment 15
- `suscheck connect …` — Increment 15

---

## Environment variables (common)

Documented in `.env.example` in the repo. Typical names include `SUSCHECK_VT_KEY`, `SUSCHECK_ABUSEIPDB_KEY`, `SUSCHECK_GITHUB_TOKEN`, `SUSCHECK_NVD_KEY`, AI-related vars. **Missing keys:** corresponding features skip; the tool should not crash.
