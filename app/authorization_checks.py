"""
Authorization check implementations for BOLA and BFLA detection.

These functions inspect HTTP responses and configuration to determine
whether an authorization control was bypassed, enforced, or inconclusive.
"""

from __future__ import annotations

from typing import Any

# Result classification constants
STATUS_POTENTIAL   = "POTENTIAL VULNERABILITY"
STATUS_NOT_DETECTED = "NOT DETECTED"
STATUS_INCONCLUSIVE = "INCONCLUSIVE"
STATUS_ERROR        = "ERROR"
STATUS_SKIPPED      = "SKIPPED"

# Severity estimates
SEVERITY_HIGH   = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW    = "Low"
SEVERITY_NONE   = "UNCONFIRMED"
SEVERITY_UNASSESSED = "UNASSESSED"

# HTTP status codes that typically indicate access denial
DENIAL_CODES = {401, 403, 404}


def classify_bola(
    *,
    owner_response: dict[str, Any],
    attacker_response: dict[str, Any],
    owner_id: int,
    attacker_id: int,
    object_id: int | str,
    owner_id_field: str = "owner_id",
    requester_id_field: str = "requested_by",
) -> dict[str, Any]:
    """
    Determine whether BOLA (Broken Object Level Authorization) was detected.

    Compares the authorized owner's response with the attacker's response to
    determine if unauthorized cross-user access occurred.

    Args:
        owner_response:     Result dict from send_request for the owner.
        attacker_response:  Result dict from send_request for the attacker.
        owner_id:           Numeric ID of the resource owner.
        attacker_id:        Numeric ID of the attacker identity.
        object_id:          The object/resource ID being tested.
        owner_id_field:     Response body field containing the owner ID.
        requester_id_field: Response body field containing the requester ID.

    Returns:
        Classification result dict.
    """
    # Network error on attacker request
    if "error" in attacker_response:
        return {
            "status": STATUS_ERROR,
            "severity": SEVERITY_UNASSESSED,
            "details": f"Network error during BOLA test: {attacker_response['error']}",
            "confidence": "N/A",
        }

    # Owner access also failed — something is wrong with the setup
    if "error" in owner_response:
        return {
            "status": STATUS_INCONCLUSIVE,
            "severity": SEVERITY_NONE,
            "details": "Owner access failed — cannot confirm ownership baseline.",
            "confidence": "Low",
        }

    att_status = attacker_response.get("status_code")
    att_body   = attacker_response.get("body", {})
    own_status = owner_response.get("status_code")
    own_body   = owner_response.get("body", {})

    # Owner cannot access their own resource — fixture or config problem
    if own_status not in (200, 201):
        return {
            "status": STATUS_INCONCLUSIVE,
            "severity": SEVERITY_NONE,
            "details": (
                f"Owner (ID {owner_id}) received HTTP {own_status} for object {object_id}. "
                "Cannot establish ownership baseline."
            ),
            "confidence": "Low",
        }

    # Attacker was denied — authorization appears to be working
    if att_status in DENIAL_CODES:
        return {
            "status": STATUS_NOT_DETECTED,
            "severity": SEVERITY_NONE,
            "details": (
                f"Attacker (ID {attacker_id}) received HTTP {att_status} "
                f"for object {object_id} owned by ID {owner_id}. "
                "Authorization appears to be enforced."
            ),
            "confidence": "High",
        }

    # Attacker got HTTP 200 — check body evidence
    if att_status in (200, 201):
        # If the tested identity is the actual owner, this is authorized owner access
        if attacker_id == owner_id:
            return {
                "status": STATUS_NOT_DETECTED,
                "severity": SEVERITY_NONE,
                "details": (
                    f"Identity ID {attacker_id} is the resource owner of object {object_id}. "
                    "Authorized access confirmed."
                ),
                "confidence": "High",
            }

        body_owner_id = att_body.get(owner_id_field)
        body_requester_id = att_body.get(requester_id_field)

        # Strong evidence: body explicitly shows cross-user ownership
        if body_owner_id == owner_id and body_requester_id == attacker_id:
            return {
                "status": STATUS_POTENTIAL,
                "severity": SEVERITY_HIGH,
                "details": (
                    f"Identity ID {attacker_id} accessed object {object_id} "
                    f"owned by ID {owner_id} and received HTTP 200 with matching "
                    "ownership evidence in the response body."
                ),
                "confidence": "High",
                "owner_id_in_response": body_owner_id,
                "requester_id_in_response": body_requester_id,
            }

        # Moderate evidence: 200 but no ownership fields to confirm
        if body_owner_id is None and body_requester_id is None:
            return {
                "status": STATUS_INCONCLUSIVE,
                "severity": SEVERITY_MEDIUM,
                "details": (
                    f"Identity ID {attacker_id} received HTTP 200 for object {object_id} "
                    f"(owner ID {owner_id}), but the response body lacks ownership fields "
                    f"({owner_id_field!r}, {requester_id_field!r}) to confirm access."
                ),
                "confidence": "Medium",
            }

        # Response has ownership fields but they don't match expected cross-user pattern
        return {
            "status": STATUS_INCONCLUSIVE,
            "severity": SEVERITY_MEDIUM,
            "details": (
                f"Identity ID {attacker_id} received HTTP 200 for object {object_id}, "
                f"but ownership evidence was ambiguous: "
                f"{owner_id_field}={body_owner_id!r}, {requester_id_field}={body_requester_id!r}."
            ),
            "confidence": "Medium",
        }

    # Unexpected status code
    return {
        "status": STATUS_INCONCLUSIVE,
        "severity": SEVERITY_NONE,
        "details": (
            f"Unexpected HTTP {att_status} during BOLA test for object {object_id}."
        ),
        "confidence": "Low",
    }


def classify_bfla(
    *,
    admin_response: dict[str, Any],
    user_response: dict[str, Any],
    user_role: str,
    required_role: str,
    endpoint: str,
    caller_role_field: str = "caller_role",
    required_role_field: str = "required_role",
) -> dict[str, Any]:
    """
    Determine whether BFLA (Broken Function Level Authorization) was detected.

    Compares the authorized admin's access with a lower-privileged user's access
    to determine if a function-level authorization control was bypassed.

    Args:
        admin_response:      Result dict from send_request for the admin user.
        user_response:       Result dict from send_request for the normal user.
        user_role:           The role of the identity being tested.
        required_role:       The role expected to be required for this endpoint.
        endpoint:            The endpoint path (for evidence).
        caller_role_field:   Response body field containing the caller's role.
        required_role_field: Response body field containing the required role.

    Returns:
        Classification result dict.
    """
    # Network error
    if "error" in user_response:
        return {
            "status": STATUS_ERROR,
            "severity": SEVERITY_UNASSESSED,
            "details": f"Network error during BFLA test: {user_response['error']}",
            "confidence": "N/A",
        }

    # Admin baseline failed — inconclusive
    if "error" in admin_response:
        return {
            "status": STATUS_INCONCLUSIVE,
            "severity": SEVERITY_NONE,
            "details": "Admin baseline request failed — cannot confirm endpoint behavior.",
            "confidence": "Low",
        }

    usr_status = user_response.get("status_code")
    usr_body   = user_response.get("body", {})
    adm_status = admin_response.get("status_code")

    # Admin cannot access — fixture or config problem
    if adm_status not in (200, 201):
        return {
            "status": STATUS_INCONCLUSIVE,
            "severity": SEVERITY_NONE,
            "details": (
                f"Admin received HTTP {adm_status} for {endpoint}. "
                "Cannot establish admin access baseline."
            ),
            "confidence": "Low",
        }

    # Non-admin user was denied — authorization enforced
    if usr_status in DENIAL_CODES:
        return {
            "status": STATUS_NOT_DETECTED,
            "severity": SEVERITY_NONE,
            "details": (
                f"User with role {user_role!r} received HTTP {usr_status} "
                f"for {endpoint} (required role: {required_role!r}). "
                "Role enforcement appears to be working."
            ),
            "confidence": "High",
        }

    # User got HTTP 200 — check role evidence
    if usr_status in (200, 201):
        # If the user role has the required role, this is authorized access
        if user_role == required_role:
            return {
                "status": STATUS_NOT_DETECTED,
                "severity": SEVERITY_NONE,
                "details": (
                    f"User with role {user_role!r} matches required role {required_role!r}. "
                    "Authorized access confirmed."
                ),
                "confidence": "High",
            }

        body_caller_role   = usr_body.get(caller_role_field)
        body_required_role = usr_body.get(required_role_field)

        # Strong evidence: body confirms role mismatch
        if body_caller_role == user_role and body_required_role == required_role:
            return {
                "status": STATUS_POTENTIAL,
                "severity": SEVERITY_HIGH,
                "details": (
                    f"User with role {user_role!r} accessed {endpoint} "
                    f"(required role: {required_role!r}) and received HTTP 200. "
                    "Response body confirms caller_role vs required_role mismatch."
                ),
                "confidence": "High",
                "caller_role_in_response":   body_caller_role,
                "required_role_in_response": body_required_role,
            }

        # Moderate evidence: 200 but no role fields
        if body_caller_role is None and body_required_role is None:
            return {
                "status": STATUS_INCONCLUSIVE,
                "severity": SEVERITY_MEDIUM,
                "details": (
                    f"User with role {user_role!r} received HTTP 200 for {endpoint} "
                    f"(required: {required_role!r}), but response lacks role fields "
                    f"({caller_role_field!r}, {required_role_field!r}) to confirm bypass."
                ),
                "confidence": "Medium",
            }

        # Ambiguous evidence
        return {
            "status": STATUS_INCONCLUSIVE,
            "severity": SEVERITY_MEDIUM,
            "details": (
                f"User with role {user_role!r} received HTTP 200 for {endpoint}, "
                f"but role evidence was ambiguous: "
                f"{caller_role_field}={body_caller_role!r}, "
                f"{required_role_field}={body_required_role!r}."
            ),
            "confidence": "Medium",
        }

    # Server error — not a confirmed vulnerability
    if usr_status and usr_status >= 500:
        return {
            "status": STATUS_INCONCLUSIVE,
            "severity": SEVERITY_NONE,
            "details": (
                f"Server returned HTTP {usr_status} for {endpoint}. "
                "Server errors are not treated as confirmed authorization bypass."
            ),
            "confidence": "Low",
        }

    return {
        "status": STATUS_INCONCLUSIVE,
        "severity": SEVERITY_NONE,
        "details": f"Unexpected HTTP {usr_status} during BFLA test for {endpoint}.",
        "confidence": "Low",
    }
