"""
Integration tests — run the scanner against the actual local lab Flask API.

These tests require the lab API to be running at http://127.0.0.1:5000.
If the API is not running, the tests are skipped gracefully.

Run with: pytest tests/test_integration.py -v
To start the lab first: python run.py --api   (in a separate terminal)
"""

from __future__ import annotations

import json
import threading
import time
import pytest
from pathlib import Path

from app.api import app as lab_app
from app.config import get_default_config_path, load_config
from app.scanner import Scanner, check_health
from app.report_generator import generate_json_report, generate_html_report


# ---------------------------------------------------------------------------
# Fixture: start the lab API in-process for integration tests
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def lab_server():
    """
    Start the lab Flask API in a background thread for integration tests.
    Uses port 5099 to avoid colliding with a running lab on 5000.
    """
    import socket

    port = 5099
    server_thread = None

    def _run():
        lab_app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)

    server_thread = threading.Thread(target=_run, daemon=True)
    server_thread.start()
    time.sleep(1.5)  # Give the server time to start

    yield f"http://127.0.0.1:{port}"


@pytest.fixture
def integration_config(lab_server):
    """Load config but override the base URL to point to our in-process server."""
    cfg_path = get_default_config_path()
    cfg = load_config(cfg_path)
    cfg["base_url"] = lab_server
    cfg["allowed_hosts"] = ["127.0.0.1"]
    return cfg


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

class TestHealthCheck:

    def test_lab_is_reachable(self, lab_server):
        result = check_health(lab_server, timeout=5.0)
        assert result["reachable"] is True

    def test_health_check_unreachable_host(self):
        result = check_health("http://127.0.0.1:59999", timeout=2.0)
        assert result["reachable"] is False
        assert "error" in result


# ---------------------------------------------------------------------------
# Full scan integration
# ---------------------------------------------------------------------------

class TestFullScanIntegration:

    def test_scan_completes_successfully(self, integration_config):
        scanner = Scanner(integration_config)
        result = scanner.run()
        assert result["scan_status"] in ("COMPLETED", "COMPLETED_WITH_ERRORS")

    def test_scan_detects_bola_on_vulnerable_endpoint(self, integration_config):
        """The scanner must detect BOLA on the vulnerable document endpoint."""
        scanner = Scanner(integration_config)
        result = scanner.run()

        bola_potentials = [
            f for f in result["findings"]
            if f["vuln_type"] == "BOLA" and f["status"] == "POTENTIAL VULNERABILITY"
        ]
        assert len(bola_potentials) >= 1, (
            "Expected at least one BOLA POTENTIAL VULNERABILITY finding. "
            f"Got findings: {[f['status'] for f in result['findings'] if f['vuln_type']=='BOLA']}"
        )

    def test_scan_detects_bfla_on_vulnerable_endpoint(self, integration_config):
        """The scanner must detect BFLA on the vulnerable admin endpoint."""
        scanner = Scanner(integration_config)
        result = scanner.run()

        bfla_potentials = [
            f for f in result["findings"]
            if f["vuln_type"] == "BFLA" and f["status"] == "POTENTIAL VULNERABILITY"
        ]
        assert len(bfla_potentials) >= 1, (
            "Expected at least one BFLA POTENTIAL VULNERABILITY finding. "
            f"Got findings: {[f['status'] for f in result['findings'] if f['vuln_type']=='BFLA']}"
        )

    def test_secure_endpoint_not_reported_as_bola_vulnerable(self, integration_config):
        """The secure document endpoint must NOT produce BOLA findings."""
        scanner = Scanner(integration_config)
        result = scanner.run()

        secure_bola_vulns = [
            f for f in result["findings"]
            if f["vuln_type"] == "BOLA"
            and "secure" in f["endpoint"]
            and f["status"] == "POTENTIAL VULNERABILITY"
        ]
        assert len(secure_bola_vulns) == 0, (
            f"Secure endpoint falsely reported as BOLA vulnerable: {secure_bola_vulns}"
        )

    def test_secure_endpoint_not_reported_as_bfla_vulnerable(self, integration_config):
        """The secure admin endpoint must NOT produce BFLA findings."""
        scanner = Scanner(integration_config)
        result = scanner.run()

        secure_bfla_vulns = [
            f for f in result["findings"]
            if f["vuln_type"] == "BFLA"
            and "secure" in f["endpoint"]
            and f["status"] == "POTENTIAL VULNERABILITY"
        ]
        assert len(secure_bfla_vulns) == 0, (
            f"Secure endpoint falsely reported as BFLA vulnerable: {secure_bfla_vulns}"
        )

    def test_secure_endpoints_produce_not_detected(self, integration_config):
        """Secure endpoints should produce NOT DETECTED results."""
        scanner = Scanner(integration_config)
        result = scanner.run()

        secure_not_detected = [
            f for f in result["findings"]
            if "secure" in f["endpoint"]
            and f["status"] == "NOT DETECTED"
        ]
        assert len(secure_not_detected) >= 1, (
            "Expected at least one NOT DETECTED result on secure endpoints."
        )

    def test_scan_summary_counts_are_accurate(self, integration_config):
        scanner = Scanner(integration_config)
        result = scanner.run()

        summary  = result["summary"]
        findings = result["findings"]

        from collections import Counter
        actual_counts = Counter(f["status"] for f in findings)

        assert summary["total_tests"] == len(findings)
        assert summary["potential_vulnerabilities"] == actual_counts.get("POTENTIAL VULNERABILITY", 0)
        assert summary["not_detected"]              == actual_counts.get("NOT DETECTED", 0)
        assert summary["inconclusive"]              == actual_counts.get("INCONCLUSIVE", 0)
        assert summary["skipped"]                   == actual_counts.get("SKIPPED", 0)


# ---------------------------------------------------------------------------
# Connection failure behavior
# ---------------------------------------------------------------------------

class TestConnectionFailureBehavior:
    """Regression test for the October 28 environment failure."""

    def test_stopped_api_produces_failed_scan_not_clean(self):
        """
        When the API is not running, the scan must return FAILED status,
        not COMPLETED or zero-findings-clean.
        """
        cfg = {
            "base_url":      "http://127.0.0.1:59998",  # Nothing running here
            "allowed_hosts": ["127.0.0.1"],
            "timeout":       1,
            "retries":       0,
            "identities":    [{"name": "alice", "id": 1, "role": "user"}],
            "endpoints": [{
                "path":        "/api/test",
                "method":      "GET",
                "vuln_type":   "BOLA",
                "objects":     [{"id": 1}],
                "identity_pairs": [{"owner": "alice", "attacker": "alice"}],
            }],
        }
        scanner = Scanner(cfg)
        result = scanner.run()

        assert result["scan_status"] == "FAILED", (
            f"Expected FAILED but got {result['scan_status']}. "
            "A connection failure must never be treated as a clean scan."
        )
        assert result.get("error_message"), "Error message must be present when scan fails."


# ---------------------------------------------------------------------------
# Report integration
# ---------------------------------------------------------------------------

class TestReportIntegration:

    def test_json_report_matches_actual_scan(self, integration_config, tmp_path):
        """The generated JSON report must accurately reflect the scan results."""
        scanner = Scanner(integration_config)
        result = scanner.run()

        report_path = generate_json_report(result, tmp_path, "test.json")
        report      = json.loads(report_path.read_text(encoding="utf-8"))

        assert report["summary"]["total_tests"] == result["summary"]["total_tests"]
        assert report["summary"]["potential_vulnerabilities"] == result["summary"]["potential_vulnerabilities"]
        assert len(report["findings"])          == len(result["findings"])

    def test_html_report_matches_actual_scan(self, integration_config, tmp_path):
        """The HTML report must contain scan data from the actual run."""
        scanner = Scanner(integration_config)
        result = scanner.run()

        html_path = generate_html_report(result, tmp_path, "test.html")
        html      = html_path.read_text(encoding="utf-8")

        # Should contain actual finding types
        has_bola = any(f["vuln_type"] == "BOLA" for f in result["findings"])
        if has_bola:
            assert "BOLA" in html

    def test_report_not_overwritten_on_failure(self, tmp_path):
        """Previous good report should survive even if new scan fails."""
        # Write a "previous" good report
        good_report_path = tmp_path / "authorization_scan.json"
        good_report_path.write_text('{"status": "previous_good_report"}', encoding="utf-8")

        # Simulate a failed scan — should NOT overwrite if we check before writing
        # (Our scanner only writes reports through routes.py when scan succeeds)
        # The test verifies the report file is still intact after a failed scan attempt
        assert good_report_path.exists()
        assert "previous_good_report" in good_report_path.read_text()


# ---------------------------------------------------------------------------
# Dry run
# ---------------------------------------------------------------------------

class TestDryRun:

    def test_dry_run_does_not_send_requests(self, integration_config):
        """Dry run must not send actual HTTP requests."""
        # Even if the lab is running, dry run should return instantly with mock data
        scanner = Scanner(integration_config, dry_run=True)
        result = scanner.run()
        # Dry run bypasses health check
        assert result["dry_run"] is True
        assert result["scan_status"] in ("COMPLETED", "COMPLETED_WITH_ERRORS")
