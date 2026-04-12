# Rules directory (`rules/`)

SusCheck loads machine-readable rules from the **`rules/`** directory at the **project root** (next to `pyproject.toml`), not from inside `src/`. At runtime, some loaders fall back to `./rules` under the current working directory if the packaged layout differs.

## Layer 2 code plugins (`*.toml` except `mcp.toml`)

**Loaded by:** `src/suscheck/modules/detectors/plugin_loader.py` via `detect_plugins()` (invoked from `code_scanner.py`).

**Why:** Language-specific and universal threat patterns (eval, IEX, `curl|bash`, etc.) live in TOML so they can be extended without editing Python.

**Mechanics:**

- For each scanned file, the loader reads `universal.toml` and, when the language is known, `{language}.toml` (e.g. `python.toml`, `bash.toml`).
- Each rule is a `[[rules]]` table with at least: `id`, `name`, `regex`, `severity`, `confidence`, `finding_type`, `description`, optional `mitre_ids`.
- Regexes are compiled at load time; matches are reported per line with `Finding` objects tagged `module="code_scanner.plugin_loader"`.

**Files today:** `universal.toml`, `python.toml`, `javascript.toml`, `bash.toml`, `powershell.toml`, `batch.toml`, `php.toml`, `java.toml`.

## Network rules (`network.toml`)

**Loaded by:** `src/suscheck/modules/detectors/network_indicators.py` (its own loader), not `plugin_loader.py`.

**Why:** Network classification patterns are kept alongside other rules on disk but applied inside the network detector’s logic.

## MCP static rules (`mcp.toml`)

**Loaded by:** `src/suscheck/modules/mcp_scanner.py` only (not the code plugin loader).

**Why:** MCP manifests are JSON capability / client configuration, not source lines—patterns are structured differently.

**Mechanics:**

- `[[restricted_tools]]` — `name_pattern` is a regex matched against tool **names** collected from JSON (e.g. under a `tools` array).
- `[[prompt_rules]]` — `regex` is matched against the **entire manifest text** for prompt-injection-style phrases.

## MITRE mapping (`mitre_mapping.json`)

**Purpose:** ATT&CK technique references attached to findings where rules specify `mitre_ids`. Consumption depends on the module that emits the finding (detectors and scanners pass IDs through to `Finding.mitre_ids`).

## What is *not* in `rules/` today

Popular-packages lists, URLhaus feeds, and other Checkpoint 1a “data files” may still be planned or live elsewhere. If a path is not in this repository, it is not documented here as present.
