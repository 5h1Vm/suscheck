# SusCheck Dashboards

This folder contains a standalone dashboard skeleton for SusCheck scan reports.

## Purpose

- Keep dashboard work separate from the main `suscheck/` package.
- Provide a simple static preview that can load a SusCheck JSON report.
- Use the existing JSON contract documented in `Checkpoints/docs/dashboard_json_contract.md`.

## Files

- `index.html` - dashboard shell
- `styles.css` - dashboard styling
- `app.js` - report loader and renderer
- `serve_dashboard.py` - dedicated local server for the dashboard

## Quick Start

1. Start the dashboard server:
   ```bash
   cd /home/shivam/Minor02/suscheck
   source venv/bin/activate
   python dashboards/serve_dashboard.py --report /path/to/report.json
   ```
2. Open the printed local URL in a browser.
3. Use a real `suscheck scan --format json` report.
4. If you do not pass `--report`, the dashboard will load without data until a report endpoint is provided.

## Default Port

- `4173`
- `4173`
- `127.0.0.1` and `localhost` are printed as clickable links by the server

## Notes

- This folder is intentionally separate from the CLI implementation.
- Unknown JSON fields are ignored.
- Required fields follow the dashboard contract in the `Checkpoints/docs/` folder.
