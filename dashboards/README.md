# SusCheck Dashboards

This folder contains a standalone dashboard workbench for SusCheck scans and reports.

## Purpose

- Keep dashboard work separate from the main `suscheck/` package.
- Run scans directly from the UI with explicit adapter/module toggles.
- Load and inspect existing SusCheck JSON reports.
- Use the existing JSON contract documented in `Checkpoints/docs/dashboard_json_contract.md`.

## Files

- `index.html` - workbench shell and controls
- `styles.css` - workbench styling
- `app.js` - scan execution client, report loader, plugin renderer
- `serve_dashboard.py` - dedicated local server and scan API (`/scan`)

## Quick Start

1. Start the dashboard server:
   ```bash
   cd /home/shivam/Minor02/suscheck
   source venv/bin/activate
   python dashboards/serve_dashboard.py --report /path/to/report.json
   ```
2. Open the printed local URL in a browser.
3. Enter a target (path, URL, repo URL, package) and click `Run Scan`, or upload a local file/archive and click `Scan Uploaded Artifact`.
4. Use adapter toggles to enable/disable Nuclei, Trivy, Grype, ZAP, and OpenVAS.
5. If you do not pass `--report`, the dashboard loads without data until a scan is run or a JSON report is loaded manually.

## Default Port

- `4173`
- `4173`
- `127.0.0.1` and `localhost` are printed as clickable links by the server

## Notes

- The dashboard server executes `python -m suscheck scan ...` from the project root.
- Uploaded scan artifacts are stored temporarily under `dashboards/.runtime/uploads/`.
- Unknown JSON fields are ignored.
- Required fields follow the dashboard contract in the `Checkpoints/docs/` folder.
