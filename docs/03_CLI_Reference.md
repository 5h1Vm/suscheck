# CLI Reference

`suscheck` uses `typer` to power its terminal interface.

## Commands

### `suscheck scan <target>`
The primary command to execute the pipeline over a file, directory (repository), or remote artifact.

**Behavior:**
- **Files:** Runs Tier 0 (VT) -> Tier 1 (Code Scanner/Config Scanner) -> Tier 2 (Semgrep).
- **Directories:** Automatically detours to **Repo Scanner (Gitleaks)** to hunt secrets and commit history risks.
- **Config Files:** Automatically detours to **Config Scanner (KICS)** for IaC/DevOps scanning.

**Key Flags:**
- `--upload-vt`: If enabled, a file with an unknown hash will literally be uploaded to VirusTotal's API. **Warning: It exposes your file publicly.**
- `--output / -o`: Change the logging format (json, terminal).
- `--report / -r`: Create a persistent report (html, markdown).
- `-h, --help`: Contextual help.

### `suscheck trust <package>`
Specifically maps **Supply Chain Trust Signals** for third-party packages (currently PyPI).

**Capabilities:**
- Proximity-based **Typosquatting** detection (e.g. `requesrs` vs `requests`).
- **Abandonment Check**: Deducts points if the package hasn't been updated in 12+ months.
- **Yanked Check**: Flags if the version was pulled by the maintainer.
- **Transitive SCA**: Resolves the full dependency tree via `deps.dev` to find hidden CVEs.

### `suscheck version`
Shows the active tool version. More importantly, it acts as a diagnostics checker, evaluating the status of the setup API Keys in `.env` (like VirusTotal, AbuseIPDB, GitHub etc.).

## Setup Configuration
SusCheck requires API tokens to access maximum capabilities. Ensure you have a `.env` configured at your user root or standard execution path:

```bash
# Inside .env
SUSCHECK_VT_KEY="your-virustotal-key-here"
# Add others as needed for subsequent increments. 
```

To load `.env` context gracefully across the CLI, we utilize the `python-dotenv` python library right at boot. No keys are hardcoded.
