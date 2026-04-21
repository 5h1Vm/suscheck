from __future__ import annotations

import argparse
import base64
import json
import re
import subprocess
import tempfile
import time
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
from urllib.parse import urlparse
import webbrowser

DEFAULT_PORT = 4173
MAX_UPLOAD_BYTES = 20 * 1024 * 1024


class DashboardRequestHandler(SimpleHTTPRequestHandler):
    """Serve dashboard assets and a real report JSON payload."""

    report_path: Path | None = None
    project_root: Path | None = None

    def do_GET(self):  # noqa: N802
        path = urlparse(self.path).path
        if path == "/report.json":
            self._serve_report()
            return
        if path == "/healthz":
            self._serve_health()
            return
        super().do_GET()

    def do_POST(self):  # noqa: N802
        path = urlparse(self.path).path
        if path == "/scan":
            self._run_scan()
            return
        self._send_json(404, {"error": "not_found", "message": "Unknown endpoint."})

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

    def _read_json_body(self) -> dict:
        content_length = int(self.headers.get("Content-Length", "0") or "0")
        if content_length <= 0:
            raise ValueError("Request body is required.")

        body = self.rfile.read(content_length)
        try:
            payload = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON request body: {exc}") from exc

        if not isinstance(payload, dict):
            raise ValueError("Request body must be a JSON object.")
        return payload

    def _runtime_dir(self) -> Path:
        root = (self.project_root or Path(__file__).resolve().parents[1])
        path = root / "dashboards" / ".runtime"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _sanitize_filename(self, value: str) -> str:
        cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
        return cleaned or "uploaded_artifact.bin"

    def _sanitize_for_log_slug(self, value: str) -> str:
        cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
        if len(cleaned) > 60:
            cleaned = cleaned[:60]
        return cleaned or "scan_target"

    def _write_scan_log(
        self,
        *,
        command: list[str],
        target: str,
        returncode: int,
        stdout_text: str,
        stderr_text: str,
        report_output: Path,
    ) -> Path:
        logs_dir = self._runtime_dir() / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)

        ts = time.strftime("%Y%m%d_%H%M%S", time.localtime())
        target_slug = self._sanitize_for_log_slug(Path(target).name or target)
        log_path = logs_dir / f"scan_{ts}_{target_slug}.log"

        report_text = [
            f"timestamp: {time.strftime('%Y-%m-%d %H:%M:%S %Z', time.localtime())}",
            f"target: {target}",
            f"returncode: {returncode}",
            f"report_output: {report_output}",
            f"command: {' '.join(command)}",
            "",
            "--- STDOUT ---",
            stdout_text,
            "",
            "--- STDERR ---",
            stderr_text,
            "",
        ]
        log_path.write_text("\n".join(report_text), encoding="utf-8")
        return log_path

    def _materialize_uploaded_target(self, upload_payload: dict) -> Path:
        if not isinstance(upload_payload, dict):
            raise ValueError("upload must be an object with name and content_b64 fields.")

        raw_name = str(upload_payload.get("name") or "uploaded_artifact.bin")
        content_b64 = upload_payload.get("content_b64")
        if not isinstance(content_b64, str) or not content_b64:
            raise ValueError("upload.content_b64 must be a non-empty base64 string.")

        try:
            data = base64.b64decode(content_b64, validate=True)
        except Exception as exc:  # pragma: no cover - defensive branch
            raise ValueError(f"upload.content_b64 is not valid base64: {exc}") from exc

        if len(data) > MAX_UPLOAD_BYTES:
            raise ValueError(f"Uploaded file is too large (max {MAX_UPLOAD_BYTES} bytes).")

        upload_dir = self._runtime_dir() / "uploads"
        upload_dir.mkdir(parents=True, exist_ok=True)
        safe_name = self._sanitize_filename(raw_name)
        target_path = upload_dir / f"{int(time.time())}_{safe_name}"
        target_path.write_bytes(data)
        return target_path

    def _build_scan_command(self, *, target: str, profile: str, output_path: Path, flags: dict) -> list[str]:
        cmd = [
            sys.executable,
            "-m",
            "suscheck",
            "scan",
            target,
            "--profile",
            profile,
            "--format",
            "json",
            "--output",
            str(output_path),
        ]

        if flags.get("ai", True):
            cmd.append("--ai")
        else:
            cmd.append("--no-ai")

        if flags.get("vt", True):
            cmd.append("--vt")
            if flags.get("upload_vt", False):
                cmd.append("--upload-vt")
        else:
            cmd.append("--no-vt")

        if flags.get("mcp_dynamic", False):
            cmd.append("--mcp-dynamic")
        else:
            cmd.append("--no-mcp-dynamic")

        if flags.get("mcp_only", False):
            cmd.append("--mcp-only")

        if flags.get("dependency_check", False):
            cmd.append("--dependency-check")
        else:
            cmd.append("--no-dependency-check")

        if flags.get("nuclei", False):
            cmd.append("--nuclei")
        else:
            cmd.append("--no-nuclei")

        if flags.get("trivy", False):
            cmd.append("--trivy")
        else:
            cmd.append("--no-trivy")

        if flags.get("grype", False):
            cmd.append("--grype")
        else:
            cmd.append("--no-grype")

        if flags.get("zap", False):
            cmd.append("--zap")
        else:
            cmd.append("--no-zap")

        if flags.get("openvas", False):
            cmd.append("--openvas")
        else:
            cmd.append("--no-openvas")

        if flags.get("verbose", False):
            cmd.append("--verbose")

        return cmd

    def _run_scan(self) -> None:
        try:
            payload = self._read_json_body()
        except ValueError as exc:
            self._send_json(400, {"error": "invalid_request", "message": str(exc)})
            return

        target = str(payload.get("target") or "").strip()
        profile = str(payload.get("profile") or "default").strip() or "default"
        timeout_seconds = int(payload.get("timeout_seconds") or 300)
        if timeout_seconds <= 0:
            timeout_seconds = 300

        flags_raw = payload.get("flags")
        flags = flags_raw if isinstance(flags_raw, dict) else {}

        try:
            if payload.get("upload"):
                uploaded = self._materialize_uploaded_target(payload["upload"])
                target = str(uploaded)
        except ValueError as exc:
            self._send_json(400, {"error": "invalid_upload", "message": str(exc)})
            return

        if not target:
            self._send_json(400, {"error": "missing_target", "message": "Provide a scan target or upload a file."})
            return

        report_output = Path(tempfile.mkstemp(prefix="suscheck_dashboard_", suffix=".json", dir=self._runtime_dir())[1])
        command = self._build_scan_command(target=target, profile=profile, output_path=report_output, flags=flags)
        project_root = self.project_root or Path(__file__).resolve().parents[1]

        try:
            proc = subprocess.run(
                command,
                cwd=str(project_root),
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            self._send_json(
                504,
                {
                    "error": "scan_timeout",
                    "message": f"Scan timed out after {timeout_seconds} seconds.",
                },
            )
            return
        except OSError as exc:
            self._send_json(
                500,
                {
                    "error": "scan_exec_failed",
                    "message": f"Unable to execute scan: {exc}",
                },
            )
            return

        stdout_text = (proc.stdout or "").strip()
        stderr_text = (proc.stderr or "").strip()
        if stdout_text and stderr_text and stdout_text == stderr_text:
            combined_output = stdout_text
        else:
            combined_output = "\n".join([part for part in [stdout_text, stderr_text] if part]).strip()

        log_path = self._write_scan_log(
            command=command,
            target=target,
            returncode=proc.returncode,
            stdout_text=stdout_text,
            stderr_text=stderr_text,
            report_output=report_output,
        )

        if proc.returncode != 0:
            self._send_json(
                500,
                {
                    "error": "scan_failed",
                    "message": f"SusCheck exited with code {proc.returncode}.",
                    "stdout": combined_output[-7000:] if combined_output else "",
                    "command": command,
                    "log_path": str(log_path),
                },
            )
            return

        if not report_output.exists():
            self._send_json(
                500,
                {
                    "error": "missing_report",
                    "message": "Scan finished but no JSON report was produced.",
                    "stdout": combined_output[-7000:] if combined_output else "",
                    "log_path": str(log_path),
                },
            )
            return

        try:
            report_payload = json.loads(report_output.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            self._send_json(
                500,
                {
                    "error": "invalid_report",
                    "message": f"Generated report could not be read: {exc}",
                    "stdout": combined_output[-7000:] if combined_output else "",
                    "log_path": str(log_path),
                },
            )
            return

        self.report_path = report_output
        latest_report = self._runtime_dir() / "latest_report.json"
        try:
            latest_report.write_text(report_output.read_text(encoding="utf-8"), encoding="utf-8")
        except OSError:
            latest_report = report_output

        self._send_json(
            200,
            {
                "status": "ok",
                "message": "Scan completed successfully.",
                "report": report_payload,
                "source_label": f"scan result {report_output.name}",
                "stdout": combined_output[-7000:] if combined_output else "",
                "report_path": str(report_output),
                "latest_report_path": str(latest_report),
                "log_path": str(log_path),
            },
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve the SusCheck dashboard skeleton.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Port to bind (default: {DEFAULT_PORT})")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    parser.add_argument("--report", type=Path, help="Path to a real SusCheck JSON report")
    parser.add_argument("--no-browser", action="store_true", help="Do not open a browser automatically")
    args = parser.parse_args()

    dashboard_dir = Path(__file__).resolve().parent
    DashboardRequestHandler.report_path = args.report
    DashboardRequestHandler.project_root = Path(__file__).resolve().parents[1]
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
