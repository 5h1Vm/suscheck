from __future__ import annotations

import argparse
import json
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
from urllib.parse import urlparse
import webbrowser

DEFAULT_PORT = 4173


class DashboardRequestHandler(SimpleHTTPRequestHandler):
    """Serve dashboard assets and a real report JSON payload."""

    report_path: Path | None = None

    def do_GET(self):  # noqa: N802
        path = urlparse(self.path).path
        if path == "/report.json":
            self._serve_report()
            return
        if path == "/healthz":
            self._serve_health()
            return
        super().do_GET()

    def _send_json(self, status_code: int, payload: dict) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_health(self) -> None:
        report_configured = self.report_path is not None
        report_exists = bool(report_configured and self.report_path and self.report_path.exists())
        self._send_json(
            200,
            {
                "status": "ok",
                "report_configured": report_configured,
                "report_exists": report_exists,
                "report_path": str(self.report_path) if self.report_path else None,
            },
        )

    def _serve_report(self) -> None:
        if self.report_path is None:
            self._send_json(
                404,
                {
                    "error": "no_report_configured",
                    "message": "No report configured. Start server with --report <path>.",
                },
            )
            return

        if not self.report_path.exists():
            self._send_json(
                404,
                {
                    "error": "report_not_found",
                    "message": f"Report path does not exist: {self.report_path}",
                },
            )
            return

        try:
            raw_payload = self.report_path.read_text(encoding="utf-8")
        except OSError as exc:
            self._send_json(
                500,
                {
                    "error": "report_read_failed",
                    "message": f"Unable to read report file: {exc}",
                },
            )
            return

        try:
            payload = json.loads(raw_payload)
        except json.JSONDecodeError as exc:
            self._send_json(
                422,
                {
                    "error": "invalid_report_json",
                    "message": f"Report file is not valid JSON: {exc}",
                },
            )
            return

        if not isinstance(payload, dict):
            self._send_json(
                422,
                {
                    "error": "invalid_report_shape",
                    "message": "Report root must be a JSON object.",
                },
            )
            return

        self._send_json(200, payload)


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve the SusCheck dashboard skeleton.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Port to bind (default: {DEFAULT_PORT})")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    parser.add_argument("--report", type=Path, help="Path to a real SusCheck JSON report")
    parser.add_argument("--no-browser", action="store_true", help="Do not open a browser automatically")
    args = parser.parse_args()

    dashboard_dir = Path(__file__).resolve().parent
    DashboardRequestHandler.report_path = args.report
    handler = partial(DashboardRequestHandler, directory=str(dashboard_dir))
    try:
        server = ThreadingHTTPServer((args.host, args.port), handler)
    except OSError as exc:
        print(f"Failed to bind dashboard server on {args.host}:{args.port}: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    url = f"http://{args.host}:{args.port}/index.html"

    print(f"SusCheck dashboard serving from: {dashboard_dir}")
    print(f"Open: {url}")
    print(f"Localhost: http://localhost:{args.port}/index.html")
    print(f"Report endpoint: http://{args.host}:{args.port}/report.json")
    if args.report:
        print(f"Using report: {args.report}")
    else:
        print("No report provided. Pass --report <path> to attach a real scan result.")
    print("Press Ctrl+C to stop.")

    if not args.no_browser:
        webbrowser.open(url)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping dashboard server...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
