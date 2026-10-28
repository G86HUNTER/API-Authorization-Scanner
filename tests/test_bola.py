"""
BOLA-specific unit tests using the authorization_checks module.
"""

from __future__ import annotations

import pytest
from app.authorization_checks import (
    classify_bola,
    STATUS_POTENTIAL,
    STATUS_NOT_DETECTED,
    STATUS_INCONCLUSIVE,
    STATUS_ERROR,
)


class TestBolaClassification:

    def _owner_resp(self, status=200):
        return {
            "status_code": status,
            "body": {"owner_id": 1, "requested_by": 1, "content": "owner content"},
        }

    def _attacker_resp(self, status=200, owner_id=1, requester_id=2):
        return {
            "status_code": status,
            "body": {
                "owner_id": owner_id,
                "requested_by": requester_id,
                "content": "attacker access",
            },
        }

    # Positive detection case
    def test_cross_user_200_with_ownership_evidence_is_potential(self):
        result = classify_bola(
            owner_response=self._owner_resp(200),
            attacker_response=self._attacker_resp(200, owner_id=1, requester_id=2),
            owner_id=1,
            attacker_id=2,
            object_id=101,
        )
        assert result["status"] == STATUS_POTENTIAL
        assert result["severity"] == "High"
        assert result["confidence"] == "High"

    # Properly denied access
    def test_403_response_is_not_detected(self):
        att = {"status_code": 403, "body": {"error": "Forbidden"}}
        result = classify_bola(
            owner_response=self._owner_resp(200),
            attacker_response=att,
            owner_id=1,
            attacker_id=2,
            object_id=101,
        )
        assert result["status"] == STATUS_NOT_DETECTED

    def test_401_response_is_not_detected(self):
        att = {"status_code": 401, "body": {"error": "Unauthorized"}}
        result = classify_bola(
            owner_response=self._owner_resp(200),
            attacker_response=att,
            owner_id=1,
            attacker_id=2,
            object_id=101,
        )
        assert result["status"] == STATUS_NOT_DETECTED

    def test_404_response_is_not_detected(self):
        att = {"status_code": 404, "body": {"error": "Not found"}}
        result = classify_bola(
            owner_response=self._owner_resp(200),
            attacker_response=att,
            owner_id=1,
            attacker_id=2,
            object_id=101,
        )
        assert result["status"] == STATUS_NOT_DETECTED

    # Missing ownership fields in response
    def test_200_without_ownership_fields_is_inconclusive(self):
        att = {"status_code": 200, "body": {"content": "some data"}}
        result = classify_bola(
            owner_response=self._owner_resp(200),
            attacker_response=att,
            owner_id=1,
            attacker_id=2,
            object_id=101,
        )
        assert result["status"] == STATUS_INCONCLUSIVE

    # Network error on attacker request
    def test_network_error_on_attacker_is_error(self):
        att = {"error": "Connection refused"}
        result = classify_bola(
            owner_response=self._owner_resp(200),
            attacker_response=att,
            owner_id=1,
            attacker_id=2,
            object_id=101,
        )
        assert result["status"] == STATUS_ERROR

    # Owner baseline failure
    def test_owner_access_fails_is_inconclusive(self):
        own = {"error": "Connection refused"}
        att = {"status_code": 200, "body": {"owner_id": 1, "requested_by": 2}}
        result = classify_bola(
            owner_response=own,
            attacker_response=att,
            owner_id=1,
            attacker_id=2,
            object_id=101,
        )
        assert result["status"] == STATUS_INCONCLUSIVE

    # Owner cannot access their own resource — bad fixture
    def test_owner_gets_403_is_inconclusive(self):
        own = {"status_code": 403, "body": {"error": "Forbidden"}}
        att = {"status_code": 200, "body": {"owner_id": 1, "requested_by": 2}}
        result = classify_bola(
            owner_response=own,
            attacker_response=att,
            owner_id=1,
            attacker_id=2,
            object_id=101,
        )
        assert result["status"] == STATUS_INCONCLUSIVE

    # Unexpected status code
    def test_unexpected_status_code_is_inconclusive(self):
        att = {"status_code": 301, "body": {}}
        result = classify_bola(
            owner_response=self._owner_resp(200),
            attacker_response=att,
            owner_id=1,
            attacker_id=2,
            object_id=101,
        )
        assert result["status"] == STATUS_INCONCLUSIVE

    # Authorized owner access works
    def test_authorized_owner_access_not_flagged(self):
        """Owner accessing their own resource — should not produce BOLA finding."""
        own_resp = {"status_code": 200, "body": {"owner_id": 1, "requested_by": 1}}
        # When owner == attacker, requester_id would equal owner_id
        att_resp = {"status_code": 200, "body": {"owner_id": 1, "requested_by": 1}}
        result = classify_bola(
            owner_response=own_resp,
            attacker_response=att_resp,
            owner_id=1,
            attacker_id=1,  # same person
            object_id=101,
        )
        # attacker_id == owner_id — no cross-user mismatch, so INCONCLUSIVE
        # (ambiguous evidence since both IDs are 1)
        assert result["status"] in (STATUS_INCONCLUSIVE, STATUS_NOT_DETECTED)

    # Custom field names
    def test_custom_owner_field_names(self):
        att = {
            "status_code": 200,
            "body": {"resource_owner": 1, "caller_id": 2},
        }
        result = classify_bola(
            owner_response=self._owner_resp(200),
            attacker_response=att,
            owner_id=1,
            attacker_id=2,
            object_id=101,
            owner_id_field="resource_owner",
            requester_id_field="caller_id",
        )
        assert result["status"] == STATUS_POTENTIAL
