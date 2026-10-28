"""
Flask backend routes for the dashboard and API endpoints.

Routes:
  GET  /                       — Dashboard UI
  GET  /health                 — Application health
  GET  /api/config             — Current scan configuration
  POST /api/validate-config    — Validate a YAML config string
  POST /api/scan/start         — Start a scan
  GET  /api/scan/status        — Latest scan status
  GET  /api/findings           — Latest findings
  GET  /api/reports            — List reports
  GET  /api/reports/<filename> — Download a specific report
  GET  /api/reports/latest/json — Download latest JSON report
  GET  /api/reports/latest/html — Download latest HTML report
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, Response, jsonify, render_template, request, send_file

from app.config import ConfigError, get_default_config_path, load_config
from app.report_generator import generate_html_report, generate_json_report, list_reports
from app.scanner import Scanner

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_REPORTS_DIR  = _PROJECT_ROOT / "reports"
_CONFIG_PATH  = get_default_config_path()


def create_app(config_path: Path | None = None, testing: bool = False) -> Flask:
    """Create and configure the Flask dashboard application."""
    app = Flask(
        __name__,
        template_folder=str(_PROJECT_ROOT / "dashboard" / "templates"),
        static_folder=str(_PROJECT_ROOT / "dashboard" / "static"),
        static_url_path="/static",
    )
    app.config["TESTING"] = testing
    app.config["CONFIG_PATH"] = str(config_path or _CONFIG_PATH)
    app.config["REPORTS_DIR"] = str(_REPORTS_DIR)

    # Shared scan state
    app.config["SCAN_STATE"] = {
        "status": "IDLE",
        "result": None,
        "started_at": None,
        "error": None,
    }
    app.config["SCAN_LOCK"] = threading.Lock()

    _register_routes(app)
    return app


# ---------------------------------------------------------------------------
# Route registration
# ---------------------------------------------------------------------------

def _register_routes(app: Flask) -> None:

    # ---- Dashboard UI -------------------------------------------------------

    @app.get("/")
    def dashboard():
        """Serve the main dashboard."""
        return render_template("dashboard.html")

    # ---- Health -------------------------------------------------------------

    @app.get("/health")
    def app_health():
        """Application health check."""
        return jsonify({"status": "ok", "service": "dashboard", "timestamp": _utcnow()})

    # ---- Configuration ------------------------------------------------------

    @app.get("/api/config")
    def get_config():
        """Return the current scan configuration (without secrets)."""
        config_path = Path(app.config["CONFIG_PATH"])
        try:
            cfg = load_config(config_path)
        except ConfigError as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception as exc:
            logger.exception("Unexpected error loading config: %s", exc)
            return jsonify({"error": "Failed to load configuration."}), 500

        return jsonify({"config": _sanitize_config(cfg), "config_path": str(config_path)})

    @app.post("/api/validate-config")
    def validate_config():
        """Validate a YAML configuration payload."""
        import yaml
        data = request.get_json(silent=True) or {}
        yaml_str = data.get("yaml", "")
        if not yaml_str:
            return jsonify({"valid": False, "error": "No YAML content provided."}), 400
        try:
            import io
            from app.config import _validate_config
            raw = yaml.safe_load(io.StringIO(yaml_str))
            _validate_config(raw)
            return jsonify({"valid": True})
        except Exception as exc:
            return jsonify({"valid": False, "error": str(exc)}), 400

    # ---- Scan ---------------------------------------------------------------

    @app.post("/api/scan/start")
    def start_scan():
        """Start a background scan. Returns 409 if a scan is already running."""
        lock: threading.Lock = app.config["SCAN_LOCK"]
        state: dict = app.config["SCAN_STATE"]
        config_path = Path(app.config["CONFIG_PATH"])

        with lock:
            if state["status"] == "RUNNING":
                return jsonify({
                    "error": "A scan is already running.",
                    "status": "RUNNING",
                }), 409

            try:
                cfg = load_config(config_path)
            except ConfigError as exc:
                return jsonify({"error": f"Configuration error: {exc}"}), 400

            dry_run = request.get_json(silent=True, force=True) or {}
            is_dry_run = bool(dry_run.get("dry_run", False))

            state["status"]     = "RUNNING"
            state["result"]     = None
            state["started_at"] = _utcnow()
            state["error"]      = None

        def _run():
            try:
                reports_dir = Path(app.config.get("REPORTS_DIR", _REPORTS_DIR))
                scanner = Scanner(cfg, dry_run=is_dry_run)
                result = scanner.run()

                if not is_dry_run:
                    json_path = generate_json_report(result, reports_dir)
                    html_path = generate_html_report(result, reports_dir)
                    result["report_files"] = {
                        "json": json_path.name,
                        "html": html_path.name,
                    }
                    # Also write a fixed-name "latest" copy
                    generate_json_report(result, reports_dir, filename="authorization_scan.json")
                    generate_html_report(result, reports_dir, filename="authorization_scan.html")

                with lock:
                    state["status"] = result.get("scan_status", "COMPLETED")
                    state["result"] = result
                    state["error"]  = result.get("error_message")

            except Exception as exc:  # noqa: BLE001
                logger.exception("Scan thread error: %s", exc)
                with lock:
                    state["status"] = "FAILED"
                    state["error"]  = str(exc)

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()

        return jsonify({
            "message": "Scan started.",
            "dry_run": is_dry_run,
            "started_at": state["started_at"],
        }), 202

    @app.get("/api/scan/status")
    def scan_status():
        """Return the current scan status."""
        state: dict = app.config["SCAN_STATE"]
        result = state.get("result") or {}
        return jsonify({
            "status":     state["status"],
            "started_at": state["started_at"],
            "error":      state["error"],
            "summary":    result.get("summary"),
        })

    @app.get("/api/findings")
    def get_findings():
        """Return findings from the latest completed scan."""
        state: dict = app.config["SCAN_STATE"]
        result = state.get("result")
        if result is None:
            return jsonify({"findings": [], "message": "No scan has been completed yet."})

        findings = result.get("findings", [])

        # Optional filters
        vuln_type = request.args.get("type", "").upper()
        status    = request.args.get("status", "").upper()
        severity  = request.args.get("severity", "")
        query     = request.args.get("q", "").lower()

        if vuln_type:
            findings = [f for f in findings if f.get("vuln_type", "").upper() == vuln_type]
        if status:
            findings = [f for f in findings if f.get("status", "").upper() == status]
        if severity:
            findings = [f for f in findings if f.get("severity", "") == severity]
        if query:
            findings = [
                f for f in findings
                if query in f.get("endpoint", "").lower()
                or query in f.get("finding_id", "").lower()
                or query in f.get("details", "").lower()
            ]

        return jsonify({
            "total":    len(findings),
            "findings": findings,
            "summary":  result.get("summary"),
            "scan_status": result.get("scan_status"),
        })

    # ---- Reports ------------------------------------------------------------

    @app.get("/api/reports")
    def list_report_files():
        """List available report files."""
        reports_dir = Path(app.config.get("REPORTS_DIR", _REPORTS_DIR))
        reports = list_reports(reports_dir)
        return jsonify({"reports": reports})

    @app.get("/api/reports/<path:filename>")
    def download_report(filename: str):
        """Download a specific report file."""
        # Prevent path traversal
        safe_name = Path(filename).name
        reports_dir = Path(app.config.get("REPORTS_DIR", _REPORTS_DIR))
        report_path = reports_dir / safe_name
        if not report_path.exists():
            return jsonify({"error": f"Report not found: {safe_name}"}), 404
        return send_file(report_path, as_attachment=True)

    @app.get("/api/reports/latest/json")
    def latest_json_report():
        reports_dir = Path(app.config.get("REPORTS_DIR", _REPORTS_DIR))
        report_path = reports_dir / "authorization_scan.json"
        if not report_path.exists():
            return jsonify({"error": "No JSON report available yet."}), 404
        return send_file(report_path, mimetype="application/json", as_attachment=True,
                         download_name="authorization_scan.json")

    @app.get("/api/reports/latest/html")
    def latest_html_report():
        reports_dir = Path(app.config.get("REPORTS_DIR", _REPORTS_DIR))
        report_path = reports_dir / "authorization_scan.html"
        if not report_path.exists():
            return jsonify({"error": "No HTML report available yet."}), 404
        return send_file(report_path, mimetype="text/html", as_attachment=True,
                         download_name="authorization_scan.html")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sanitize_config(cfg: dict) -> dict:
    """Remove any secret fields from config before sending to the client."""
    REDACT_KEYS = {"password", "secret", "token", "api_key", "auth"}
    result = {}
    for k, v in cfg.items():
        if k.lower() in REDACT_KEYS:
            result[k] = "**REDACTED**"
        elif isinstance(v, dict):
            result[k] = _sanitize_config(v)
        elif isinstance(v, list):
            result[k] = [
                _sanitize_config(item) if isinstance(item, dict) else item
                for item in v
            ]
        else:
            result[k] = v
    return result
