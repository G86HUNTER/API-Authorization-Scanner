"""
Dashboard backend routes tests — using Flask's test client.
"""

from __future__ import annotations

import json
import pytest
from pathlib import Path

from app.routes import create_app


@pytest.fixture
def app(tmp_path):
    """Create a test dashboard app with a temp reports dir and valid config."""
    config_path = Path(__file__).resolve().parent.parent / "config" / "scan_config.yaml"
    a = create_app(config_path=config_path, testing=True)
    a.config["REPORTS_DIR"] = str(tmp_path / "reports")
    (tmp_path / "reports").mkdir(parents=True, exist_ok=True)
    return a


@pytest.fixture
def client(app):
    with app.test_client() as c:
        yield c


class TestHealthEndpoint:

    def test_health_returns_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert data["service"] == "dashboard"


class TestDashboardUI:

    def test_dashboard_renders_html(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert b"API Auth Scanner" in resp.data or b"Authorization" in resp.data


class TestConfigEndpoint:

    def test_config_returns_200(self, client):
        resp = client.get("/api/config")
        assert resp.status_code == 200

    def test_config_contains_base_url(self, client):
        resp = client.get("/api/config")
        data = resp.get_json()
        assert "config" in data
        assert "base_url" in data["config"]

    def test_config_contains_identities(self, client):
        resp = client.get("/api/config")
        data = resp.get_json()
        identities = data["config"]["identities"]
        assert len(identities) > 0

    def test_config_contains_endpoints(self, client):
        resp = client.get("/api/config")
        data = resp.get_json()
        endpoints = data["config"]["endpoints"]
        assert len(endpoints) > 0


class TestScanStatus:

    def test_initial_status_is_idle(self, client):
        resp = client.get("/api/scan/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "IDLE"

    def test_status_has_no_error_initially(self, client):
        resp = client.get("/api/scan/status")
        data = resp.get_json()
        assert data["error"] is None


class TestFindingsEndpoint:

    def test_findings_returns_empty_before_scan(self, client):
        resp = client.get("/api/findings")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["findings"] == []

    def test_findings_filter_by_type(self, client):
        # No scan run yet — should return empty for any filter
        resp = client.get("/api/findings?type=BOLA")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["findings"] == []


class TestReportsEndpoint:

    def test_reports_returns_list(self, client):
        resp = client.get("/api/reports")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "reports" in data
        assert isinstance(data["reports"], list)

    def test_no_reports_returns_empty_list(self, client):
        resp = client.get("/api/reports")
        data = resp.get_json()
        assert data["reports"] == []

    def test_latest_json_not_found_before_scan(self, client):
        resp = client.get("/api/reports/latest/json")
        assert resp.status_code == 404

    def test_latest_html_not_found_before_scan(self, client):
        resp = client.get("/api/reports/latest/html")
        assert resp.status_code == 404

    def test_nonexistent_report_returns_404(self, client):
        resp = client.get("/api/reports/nonexistent.json")
        assert resp.status_code == 404

    def test_path_traversal_blocked(self, client):
        """Path traversal must not serve files outside reports dir."""
        resp = client.get("/api/reports/../run.py")
        assert resp.status_code == 404

    def test_reports_listed_after_creation(self, client, app, tmp_path):
        """After creating a report file, it should appear in the list."""
        from app.report_generator import generate_json_report
        result = {
            "scanner_version": "2.0.0", "scan_status": "COMPLETED",
            "started_at": "2026-10-28T17:00:00Z", "completed_at": "2026-10-28T17:00:05Z",
            "target": "http://127.0.0.1:5000", "dry_run": False,
            "summary": {"total_tests": 0, "potential_vulnerabilities": 0,
                        "not_detected": 0, "inconclusive": 0, "errors": 0, "skipped": 0},
            "findings": [],
        }
        reports_dir = Path(app.config["REPORTS_DIR"])
        generate_json_report(result, reports_dir, "authorization_scan.json")

        resp = client.get("/api/reports")
        data = resp.get_json()
        names = [r["filename"] for r in data["reports"]]
        assert "authorization_scan.json" in names


class TestScanStart:

    def test_duplicate_scan_returns_409(self, client, app):
        """Starting a second scan while one is running should return 409."""
        # Manually set state to RUNNING
        app.config["SCAN_STATE"]["status"] = "RUNNING"
        resp = client.post("/api/scan/start", json={})
        assert resp.status_code == 409
        # Reset
        app.config["SCAN_STATE"]["status"] = "IDLE"

    def test_dry_run_scan_starts_successfully(self, client):
        resp = client.post("/api/scan/start", json={"dry_run": True})
        assert resp.status_code == 202
        data = resp.get_json()
        assert "started" in data["message"].lower() or "scan" in data["message"].lower()
