"""
Local test lab API unit tests — using Flask's test client.
"""

from __future__ import annotations

import pytest
from app.api import app as lab_app


@pytest.fixture
def client():
    lab_app.config["TESTING"] = True
    with lab_app.test_client() as c:
        yield c


class TestHomeEndpoint:

    def test_home_returns_200(self, client):
        resp = client.get("/")
        assert resp.status_code == 200

    def test_home_returns_json(self, client):
        resp = client.get("/")
        data = resp.get_json()
        assert data["status"] == "running"

    def test_health_returns_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"


class TestWhoami:

    def test_known_user_returns_identity(self, client):
        resp = client.get("/api/whoami", headers={"X-Test-User": "alice"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["id"]   == 1
        assert data["role"] == "user"

    def test_unknown_user_returns_401(self, client):
        resp = client.get("/api/whoami", headers={"X-Test-User": "nobody"})
        assert resp.status_code == 401

    def test_missing_header_returns_401(self, client):
        resp = client.get("/api/whoami")
        assert resp.status_code == 401


class TestVulnerableDocumentEndpoint:
    """Tests for /api/documents/<id> — intentionally vulnerable BOLA fixture."""

    def test_owner_can_access_own_document(self, client):
        resp = client.get("/api/documents/101", headers={"X-Test-User": "alice"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["owner_id"] == 1

    def test_nonowner_can_also_access_document_bola_fixture(self, client):
        """This should return 200 — it's the vulnerable endpoint."""
        resp = client.get("/api/documents/101", headers={"X-Test-User": "bob"})
        assert resp.status_code == 200
        data = resp.get_json()
        # Ownership not enforced — BOLA vulnerability
        assert data["owner_id"]    == 1
        assert data["requested_by"] == 2

    def test_missing_document_returns_404(self, client):
        resp = client.get("/api/documents/9999", headers={"X-Test-User": "alice"})
        assert resp.status_code == 404

    def test_unknown_user_returns_401(self, client):
        resp = client.get("/api/documents/101", headers={"X-Test-User": "nobody"})
        assert resp.status_code == 401

    def test_bob_can_access_alices_doc_bola(self, client):
        """Core BOLA test: non-owner gets 200 — vulnerability present."""
        resp = client.get("/api/documents/101", headers={"X-Test-User": "bob"})
        assert resp.status_code == 200

    def test_alice_can_access_bobs_doc_bola(self, client):
        resp = client.get("/api/documents/102", headers={"X-Test-User": "alice"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["owner_id"] == 2  # owned by bob


class TestSecureDocumentEndpoint:
    """Tests for /api/documents/secure/<id> — SECURE fixture."""

    def test_owner_can_access_own_document(self, client):
        resp = client.get("/api/documents/secure/101", headers={"X-Test-User": "alice"})
        assert resp.status_code == 200

    def test_nonowner_gets_403(self, client):
        resp = client.get("/api/documents/secure/101", headers={"X-Test-User": "bob"})
        assert resp.status_code == 403

    def test_admin_can_access_any_document(self, client):
        resp = client.get("/api/documents/secure/101", headers={"X-Test-User": "admin"})
        assert resp.status_code == 200

    def test_missing_document_returns_404(self, client):
        resp = client.get("/api/documents/secure/9999", headers={"X-Test-User": "alice"})
        assert resp.status_code == 404

    def test_unknown_user_returns_401(self, client):
        resp = client.get("/api/documents/secure/101", headers={"X-Test-User": "nobody"})
        assert resp.status_code == 401


class TestVulnerableAdminEndpoint:
    """Tests for /api/admin — intentionally vulnerable BFLA fixture."""

    def test_admin_can_access(self, client):
        resp = client.get("/api/admin", headers={"X-Test-User": "admin"})
        assert resp.status_code == 200

    def test_normal_user_can_also_access_bfla_fixture(self, client):
        """This should return 200 — it's the vulnerable endpoint."""
        resp = client.get("/api/admin", headers={"X-Test-User": "bob"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["caller_role"]   == "user"
        assert data["required_role"] == "admin"

    def test_unknown_user_returns_401(self, client):
        resp = client.get("/api/admin", headers={"X-Test-User": "nobody"})
        assert resp.status_code == 401


class TestSecureAdminEndpoint:
    """Tests for /api/admin/secure — SECURE fixture."""

    def test_admin_can_access(self, client):
        resp = client.get("/api/admin/secure", headers={"X-Test-User": "admin"})
        assert resp.status_code == 200

    def test_normal_user_gets_403(self, client):
        resp = client.get("/api/admin/secure", headers={"X-Test-User": "bob"})
        assert resp.status_code == 403
        data = resp.get_json()
        assert data["caller_role"]   == "user"
        assert data["required_role"] == "admin"

    def test_alice_gets_403(self, client):
        resp = client.get("/api/admin/secure", headers={"X-Test-User": "alice"})
        assert resp.status_code == 403

    def test_unknown_user_gets_401(self, client):
        resp = client.get("/api/admin/secure", headers={"X-Test-User": "nobody"})
        assert resp.status_code == 401
