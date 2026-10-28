"""
BFLA-specific unit tests using the authorization_checks module.
"""

from __future__ import annotations

import pytest
from app.authorization_checks import (
    classify_bfla,
    STATUS_POTENTIAL,
    STATUS_NOT_DETECTED,
    STATUS_INCONCLUSIVE,
    STATUS_ERROR,
)


class TestBflaClassification:

    def _admin_resp(self, status=200):
        return {
            "status_code": status,
            "body": {"message": "Admin accessed.", "caller_role": "admin"},
        }

    def _user_resp(self, status=200, caller_role="user", required_role="admin"):
        return {
            "status_code": status,
            "body": {
                "caller_role": caller_role,
                "required_role": required_role,
                "message": "Function accessed.",
            },
        }

    # Positive detection
    def test_user_gets_200_with_role_evidence_is_potential(self):
        result = classify_bfla(
            admin_response=self._admin_resp(200),
            user_response=self._user_resp(200, "user", "admin"),
            user_role="user",
            required_role="admin",
            endpoint="/api/admin",
        )
        assert result["status"] == STATUS_POTENTIAL
        assert result["severity"] == "High"
        assert result["confidence"] == "High"

    # Role enforced
    def test_403_response_is_not_detected(self):
        usr = {"status_code": 403, "body": {"error": "Forbidden"}}
        result = classify_bfla(
            admin_response=self._admin_resp(200),
            user_response=usr,
            user_role="user",
            required_role="admin",
            endpoint="/api/admin/secure",
        )
        assert result["status"] == STATUS_NOT_DETECTED

    def test_401_response_is_not_detected(self):
        usr = {"status_code": 401, "body": {"error": "Unauthorized"}}
        result = classify_bfla(
            admin_response=self._admin_resp(200),
            user_response=usr,
            user_role="user",
            required_role="admin",
            endpoint="/api/admin/secure",
        )
        assert result["status"] == STATUS_NOT_DETECTED

    # Missing role fields
    def test_200_without_role_fields_is_inconclusive(self):
        usr = {"status_code": 200, "body": {"message": "done"}}
        result = classify_bfla(
            admin_response=self._admin_resp(200),
            user_response=usr,
            user_role="user",
            required_role="admin",
            endpoint="/api/admin",
        )
        assert result["status"] == STATUS_INCONCLUSIVE

    # Network error
    def test_network_error_on_user_request_is_error(self):
        usr = {"error": "Connection refused"}
        result = classify_bfla(
            admin_response=self._admin_resp(200),
            user_response=usr,
            user_role="user",
            required_role="admin",
            endpoint="/api/admin",
        )
        assert result["status"] == STATUS_ERROR

    # Admin baseline failure
    def test_admin_baseline_failure_is_inconclusive(self):
        adm = {"error": "Connection refused"}
        usr = self._user_resp(200)
        result = classify_bfla(
            admin_response=adm,
            user_response=usr,
            user_role="user",
            required_role="admin",
            endpoint="/api/admin",
        )
        assert result["status"] == STATUS_INCONCLUSIVE

    # Admin cannot access — bad fixture
    def test_admin_gets_403_is_inconclusive(self):
        adm = {"status_code": 403, "body": {"error": "Forbidden"}}
        usr = self._user_resp(200)
        result = classify_bfla(
            admin_response=adm,
            user_response=usr,
            user_role="user",
            required_role="admin",
            endpoint="/api/admin",
        )
        assert result["status"] == STATUS_INCONCLUSIVE

    # Server error — not a confirmed vulnerability
    def test_500_server_error_is_inconclusive_not_vulnerability(self):
        usr = {"status_code": 500, "body": {"error": "Internal Server Error"}}
        result = classify_bfla(
            admin_response=self._admin_resp(200),
            user_response=usr,
            user_role="user",
            required_role="admin",
            endpoint="/api/admin",
        )
        assert result["status"] == STATUS_INCONCLUSIVE

    # Authorized admin access works
    def test_authorized_admin_access_not_flagged_as_bfla(self):
        """Admin accessing admin function — should not detect BFLA."""
        adm_resp = self._admin_resp(200)
        # Admin as the "user" being tested — should be fine
        usr_resp = {
            "status_code": 200,
            "body": {"caller_role": "admin", "required_role": "admin"},
        }
        result = classify_bfla(
            admin_response=adm_resp,
            user_response=usr_resp,
            user_role="admin",
            required_role="admin",
            endpoint="/api/admin",
        )
        # caller_role == required_role, so ambiguous evidence (not user vs admin)
        assert result["status"] in (STATUS_INCONCLUSIVE, STATUS_NOT_DETECTED)

    # Custom field names
    def test_custom_role_field_names(self):
        usr = {
            "status_code": 200,
            "body": {"identity_role": "user", "needed_role": "admin"},
        }
        result = classify_bfla(
            admin_response=self._admin_resp(200),
            user_response=usr,
            user_role="user",
            required_role="admin",
            endpoint="/api/admin",
            caller_role_field="identity_role",
            required_role_field="needed_role",
        )
        assert result["status"] == STATUS_POTENTIAL
