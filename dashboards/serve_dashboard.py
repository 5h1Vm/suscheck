from __future__ import annotations

import argparse
import json
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import webbrowser

DEFAULT_PORT = 4173


class DashboardRequestHandler(SimpleHTTPRequestHandler):
    """Serve dashboard assets and a real report JSON payload."""

    report_path: Path | None = None

    def do_GET(self):  # noqa: N802
        if self.path in {"/report.json", "report.json"}:
            self._serve_report()
            return
        super().do_GET()

    def _serve_report(self) -> None:
        if self.report_path is None or not self.report_path.exists():
            self.send_error(404, "No report configured")
            return

        payload = json.loads(self.report_path.read_text(encoding="utf-8"))
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


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
    server = ThreadingHTTPServer((args.host, args.port), handler)
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
