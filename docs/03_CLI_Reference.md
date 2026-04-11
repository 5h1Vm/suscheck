# CLI Reference

`suscheck` uses `typer` to power its terminal interface.

## Commands

### `suscheck scan <target>`
The primary command to execute the pipeline over a file, URL, or package.

**Key Flags:**
- `--upload-vt`: If enabled, a file with an unknown hash will literally be uploaded to VirusTotal's API for dynamic sandboxing and evaluation. **Warning: It exposes your file publicly.**
- `--output / -o`: Change the logging/reporting format (currently terminal).
- `--report / -r`: Create a persistent formatted report (html, markdown).
- `--verbose / -v`: Show extensive outputs.
- `-h, --help`: See detailed contextual help instructions.

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
