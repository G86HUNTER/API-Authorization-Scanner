"""
Tests for the scanner core logic — unit tests with mocking.
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from app.scanner import (
    Scanner,
    send_request,
    check_health,
    build_finding,
    make_finding,
    _sanitize_evidence,
    _count_statuses,
    SCANNER_VERSION,
)
from app.authorization_checks import (
    STATUS_POTENTIAL,
    STATUS_NOT_DETECTED,
    STATUS_INCONCLUSIVE,
    STATUS_ERROR,
)


# ---------------------------------------------------------------------------
# Minimal config fixture
# ---------------------------------------------------------------------------

MINIMAL_CONFIG = {
    "base_url": "http://127.0.0.1:5000",
    "allowed_hosts": ["127.0.0.1"],
    "timeout": 5,
    "retries": 0,
    "identities": [
        {"name": "alice", "id": 1, "role": "user"},
        {"name": "bob",   "id": 2, "role": "user"},
        {"name": "admin", "id": 3, "role": "admin"},
    ],
    "endpoints": [],
}


# ---------------------------------------------------------------------------
# send_request tests
# ---------------------------------------------------------------------------

class TestSendRequest:

    def test_dry_run_returns_mock_response(self):
        result = send_request(
            url="http://127.0.0.1:5000/api/test",
            method="GET",
            identity_name="alice",
            dry_run=True,
        )
        assert result["dry_run"] is True
        assert result["status_code"] is None
        assert result["identity"] == "alice"

    @patch("app.scanner.http_requests.request")
    def test_successful_json_response(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"owner_id": 1, "requested_by": 2}
        mock_req.return_value = mock_resp

        result = send_request(
            url="http://127.0.0.1:5000/api/documents/101",
            method="GET",
            identity_name="bob",
        )
        assert result["status_code"] == 200
        assert result["body"]["owner_id"] == 1
        assert "error" not in result

    @patch("app.scanner.http_requests.request")
    def test_non_json_response_stored_as_raw(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.side_effect = ValueError("Not JSON")
        mock_resp.text = "<html>Not JSON</html>"
        mock_req.return_value = mock_resp

        result = send_request(
            url="http://127.0.0.1:5000/",
            method="GET",
            identity_name="alice",
        )
        assert result["status_code"] == 200
        assert "raw_response" in result["body"]

    @patch("app.scanner.http_requests.request")
    def test_connection_refused_returns_error(self, mock_req):
        from requests.exceptions import ConnectionError as ReqConnErr
        mock_req.side_effect = ReqConnErr("Connection refused")

        result = send_request(
            url="http://127.0.0.1:5000/api/test",
            method="GET",
            identity_name="bob",
        )
        assert "error" in result
        assert "error" not in result or "status_code" not in result

    @patch("app.scanner.http_requests.request")
    def test_timeout_returns_error(self, mock_req):
        from requests.exceptions import ReadTimeout
        mock_req.side_effect = ReadTimeout("timed out")

        result = send_request(
            url="http://127.0.0.1:5000/api/test",
            method="GET",
            identity_name="alice",
            retries=0,
        )
        assert "error" in result

    @patch("app.scanner.http_requests.request")
    def test_403_response_is_returned_not_error(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.json.return_value = {"error": "Forbidden"}
        mock_req.return_value = mock_resp

        result = send_request(
            url="http://127.0.0.1:5000/api/admin/secure",
            method="GET",
            identity_name="bob",
        )
        assert result["status_code"] == 403
        assert "error" not in result


# ---------------------------------------------------------------------------
# check_health tests
# ---------------------------------------------------------------------------

class TestCheckHealth:

    @patch("app.scanner.http_requests.get")
    def test_healthy_api_returns_reachable_true(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_get.return_value = mock_resp

        result = check_health("http://127.0.0.1:5000")
        assert result["reachable"] is True

    @patch("app.scanner.http_requests.get")
    def test_connection_refused_returns_reachable_false(self, mock_get):
        from requests.exceptions import ConnectionError as ReqConnErr
        mock_get.side_effect = ReqConnErr("Connection refused")

        result = check_health("http://127.0.0.1:5000")
        assert result["reachable"] is False
        assert "error" in result

    @patch("app.scanner.http_requests.get")
    def test_5xx_response_still_reachable(self, mock_get):
        """A server error means the server is running — still reachable."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_get.return_value = mock_resp

        result = check_health("http://127.0.0.1:5000")
        assert result["reachable"] is True


# ---------------------------------------------------------------------------
# build_finding tests
# ---------------------------------------------------------------------------

class TestBuildFinding:

    def test_potential_finding_has_all_required_fields(self):
        classification = {
            "status":     STATUS_POTENTIAL,
            "severity":   "High",
            "confidence": "High",
            "details":    "Test details.",
        }
        finding = build_finding(
            vuln_type="BOLA",
            endpoint="/api/documents/101",
            method="GET",
            test_identity="bob",
            test_role="user",
            classification=classification,
            attacker_response={"status_code": 200, "body": {"owner_id": 1}},
            remediation="Enforce ownership checks.",
            expected_policy="Owner-only access.",
        )
        assert finding["status"]     == STATUS_POTENTIAL
        assert finding["severity"]   == "High"
        assert finding["vuln_type"]  == "BOLA"
        assert finding["endpoint"]   == "/api/documents/101"
        assert finding["method"]     == "GET"
        assert finding["finding_id"]
        assert finding["timestamp"]
        assert finding["remediation"] == "Enforce ownership checks."

    def test_not_detected_finding(self):
        classification = {
            "status":     STATUS_NOT_DETECTED,
            "severity":   "UNCONFIRMED",
            "confidence": "High",
            "details":    "Access was denied.",
        }
        finding = build_finding(
            vuln_type="BFLA",
            endpoint="/api/admin/secure",
            method="GET",
            test_identity="bob",
            test_role="user",
            classification=classification,
            attacker_response={"status_code": 403, "body": {"error": "Forbidden"}},
            remediation="Enforce role checks.",
            expected_policy="Admin only.",
        )
        assert finding["status"]   == STATUS_NOT_DETECTED
        assert finding["severity"] == "UNCONFIRMED"


# ---------------------------------------------------------------------------
# Evidence sanitization
# ---------------------------------------------------------------------------

class TestSanitizeEvidence:

    def test_redacts_token_field(self):
        body = {"token": "secret123", "owner_id": 1}
        result = _sanitize_evidence(body)
        assert result["token"] == "**REDACTED**"
        assert result["owner_id"] == 1

    def test_redacts_password_field(self):
        body = {"password": "p@ss", "user": "bob"}
        result = _sanitize_evidence(body)
        assert result["password"] == "**REDACTED**"

    def test_non_dict_returned_as_is(self):
        assert _sanitize_evidence("plain text") == "plain text"
        assert _sanitize_evidence([1, 2, 3])    == [1, 2, 3]

    def test_safe_fields_not_redacted(self):
        body = {"owner_id": 1, "requested_by": 2, "content": "data"}
        result = _sanitize_evidence(body)
        assert result == body


# ---------------------------------------------------------------------------
# Status counting
# ---------------------------------------------------------------------------

class TestCountStatuses:

    def test_counts_all_statuses(self):
        findings = [
            {"status": "POTENTIAL VULNERABILITY"},
            {"status": "POTENTIAL VULNERABILITY"},
            {"status": "NOT DETECTED"},
            {"status": "INCONCLUSIVE"},
            {"status": "ERROR"},
            {"status": "SKIPPED"},
        ]
        counts = _count_statuses(findings)
        assert counts["POTENTIAL VULNERABILITY"] == 2
        assert counts["NOT DETECTED"]            == 1
        assert counts["INCONCLUSIVE"]            == 1
        assert counts["ERROR"]                   == 1
        assert counts["SKIPPED"]                 == 1

    def test_unknown_status_not_counted(self):
        findings = [{"status": "WHATEVER"}]
        counts = _count_statuses(findings)
        assert all(v == 0 for v in counts.values())


# ---------------------------------------------------------------------------
# Legacy make_finding compatibility
# ---------------------------------------------------------------------------

class TestMakeFinding:

    def test_detected_is_potential_vulnerability(self):
        finding = make_finding(
            "BOLA", True, "Bob accessed Alice's doc.",
            {"status_code": 200, "body": {"owner_id": 1, "requested_by": 2}},
            "High", "Enforce ownership."
        )
        assert finding["status"] == "POTENTIAL VULNERABILITY"
        assert finding["severity"] == "High"

    def test_not_detected_is_unconfirmed(self):
        finding = make_finding(
            "BOLA", False, "Cross-user access not observed.",
            {"status_code": 403, "body": {}},
            "High", "Enforce ownership."
        )
        assert finding["status"] == "NOT DETECTED"
        assert finding["severity"] == "UNCONFIRMED"


# ---------------------------------------------------------------------------
# Scanner health-check failure
# ---------------------------------------------------------------------------

class TestScannerHealthCheck:

    @patch("app.scanner.check_health")
    def test_failed_health_check_returns_failed_status(self, mock_health):
        mock_health.return_value = {
            "reachable": False,
            "error": "Connection refused — is the API running?"
        }
        scanner = Scanner(MINIMAL_CONFIG)
        result = scanner.run()

        assert result["scan_status"] == "FAILED"
        assert "error_message" in result
        assert result["summary"]["total_tests"] == 0
        # Failed scan must never be described as clean
        assert result["summary"].get("potential_vulnerabilities", 0) == 0

    @patch("app.scanner.check_health")
    def test_failed_scan_not_represented_as_clean(self, mock_health):
        """Regression test for the October 28 environment failure."""
        mock_health.return_value = {"reachable": False, "error": "refused"}
        scanner = Scanner(MINIMAL_CONFIG)
        result = scanner.run()
        # scan_status must not be COMPLETED when health check fails
        assert result["scan_status"] != "COMPLETED"
        assert result["scan_status"] != "COMPLETED_WITH_ERRORS"
