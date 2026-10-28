"""
Local Test Lab API — intentionally vulnerable and secure fixtures.

This module provides a controlled Flask API for security testing only.
It MUST NOT be exposed to public network interfaces.

Routes:
  /                              — health / home
  /health                        — JSON health check
  /api/documents/<id>            — VULNERABLE: no ownership check (BOLA fixture)
  /api/documents/secure/<id>     — SECURE: ownership enforced
  /api/admin                     — VULNERABLE: no role check (BFLA fixture)
  /api/admin/secure              — SECURE: role enforced
  /api/whoami                    — returns caller identity
"""

from flask import Flask, jsonify, request

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Test identities — local lab only
# ---------------------------------------------------------------------------
USERS: dict[str, dict] = {
    "alice": {"id": 1, "role": "user"},
    "bob":   {"id": 2, "role": "user"},
    "carol": {"id": 3, "role": "user"},
    "admin": {"id": 4, "role": "admin"},
}

# ---------------------------------------------------------------------------
# Test documents — local lab only
# ---------------------------------------------------------------------------
DOCUMENTS: dict[int, dict] = {
    101: {"owner_id": 1, "title": "Alice's Report",   "content": "Confidential content owned by Alice."},
    102: {"owner_id": 2, "title": "Bob's Report",     "content": "Confidential content owned by Bob."},
    103: {"owner_id": 3, "title": "Carol's Report",   "content": "Confidential content owned by Carol."},
}


def _get_test_user() -> dict | None:
    """Resolve the simulated test identity from the request header."""
    username = request.headers.get("X-Test-User", "").strip()
    return USERS.get(username)


def _identity_response(user: dict) -> dict:
    """Return a safe subset of user data (no secrets)."""
    return {"id": user["id"], "role": user["role"]}


# ---------------------------------------------------------------------------
# Home / Health
# ---------------------------------------------------------------------------

@app.get("/")
def home():
    """Home endpoint — confirms the lab is running."""
    return jsonify({
        "project": "API Authorization Security Testing Framework",
        "status": "running",
        "environment": "local-test-lab",
        "warning": "For authorized security testing only. Not for production use.",
    })


@app.get("/health")
def health():
    """Lightweight health check for pre-scan availability checks."""
    return jsonify({"status": "ok", "service": "api-lab"})


@app.get("/api/whoami")
def whoami():
    """Return the current test identity."""
    user = _get_test_user()
    if user is None:
        return jsonify({"error": "Unknown test identity. Use X-Test-User header."}), 401
    return jsonify({"username": request.headers.get("X-Test-User"), **_identity_response(user)})


# ---------------------------------------------------------------------------
# BOLA Fixtures
# ---------------------------------------------------------------------------

@app.get("/api/documents/<int:document_id>")
def get_document_vulnerable(document_id: int):
    """
    INTENTIONALLY VULNERABLE LAB FIXTURE — BOLA.
    Ownership is NOT checked. Any authenticated user can read any document.
    This fixture exists to test that the scanner correctly detects BOLA.
    """
    user = _get_test_user()
    if user is None:
        return jsonify({"error": "Unknown test identity. Use X-Test-User header."}), 401

    doc = DOCUMENTS.get(document_id)
    if doc is None:
        return jsonify({"error": "Document not found."}), 404

    # No ownership check — intentional vulnerability
    return jsonify({
        "document_id": document_id,
        "owner_id":    doc["owner_id"],
        "requested_by": user["id"],
        "title":       doc["title"],
        "content":     doc["content"],
    })


@app.get("/api/documents/secure/<int:document_id>")
def get_document_secure(document_id: int):
    """
    SECURE LAB FIXTURE — BOLA.
    Ownership IS checked. Cross-user access is denied with HTTP 403.
    This fixture exists to test that the scanner does NOT raise false positives.
    """
    user = _get_test_user()
    if user is None:
        return jsonify({"error": "Unknown test identity. Use X-Test-User header."}), 401

    doc = DOCUMENTS.get(document_id)
    if doc is None:
        return jsonify({"error": "Document not found."}), 404

    # Ownership enforced — this is how it should work
    if doc["owner_id"] != user["id"] and user["role"] != "admin":
        return jsonify({
            "error": "Access denied. You do not own this resource.",
            "document_id": document_id,
            "owner_id": doc["owner_id"],
            "requested_by": user["id"],
        }), 403

    return jsonify({
        "document_id": document_id,
        "owner_id":    doc["owner_id"],
        "requested_by": user["id"],
        "title":       doc["title"],
        "content":     doc["content"],
    })


# ---------------------------------------------------------------------------
# BFLA Fixtures
# ---------------------------------------------------------------------------

@app.get("/api/admin")
def admin_function_vulnerable():
    """
    INTENTIONALLY VULNERABLE LAB FIXTURE — BFLA.
    Role is NOT checked. Any authenticated user can call this admin function.
    This fixture exists to test that the scanner correctly detects BFLA.
    """
    user = _get_test_user()
    if user is None:
        return jsonify({"error": "Unknown test identity. Use X-Test-User header."}), 401

    # No role check — intentional vulnerability
    return jsonify({
        "message":       "Admin function accessed.",
        "requested_by":  user["id"],
        "caller_role":   user["role"],
        "required_role": "admin",
        "warning":       "INTENTIONALLY VULNERABLE: role not enforced.",
    })


@app.get("/api/admin/secure")
def admin_function_secure():
    """
    SECURE LAB FIXTURE — BFLA.
    Role IS checked. Non-admin callers are denied with HTTP 403.
    This fixture exists to test that the scanner does NOT raise false positives.
    """
    user = _get_test_user()
    if user is None:
        return jsonify({"error": "Unknown test identity. Use X-Test-User header."}), 401

    if user["role"] != "admin":
        return jsonify({
            "error": "Access denied. Admin role required.",
            "caller_role":   user["role"],
            "required_role": "admin",
        }), 403

    return jsonify({
        "message":      "Admin function accessed by authorized user.",
        "requested_by": user["id"],
        "caller_role":  user["role"],
    })


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # IMPORTANT: Bind to 127.0.0.1 only — never expose to public interfaces.
    app.run(host="127.0.0.1", port=5000, debug=False)
