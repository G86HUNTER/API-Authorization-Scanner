"""
Core scanning engine for the API Authorization Security Testing Framework.

Reads a validated configuration, sends controlled HTTP requests to the
configured endpoints, applies BOLA/BFLA classification logic, and
returns structured findings.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

import requests as http_requests
from requests.exceptions import ConnectionError, ReadTimeout, RequestException

from app.authorization_checks import (
    STATUS_ERROR,
    STATUS_INCONCLUSIVE,
    STATUS_SKIPPED,
    classify_bola,
    classify_bfla,
)

logger = logging.getLogger(__name__)

# Scanner version
SCANNER_VERSION = "2.0.0"

REMEDIATION: dict[str, str] = {
    "BOLA": (
        "Enforce object-level authorization on every request. "
        "Verify that the authenticated user is permitted to access "
        "the requested object ID specifically. "
        "Never rely on the client to supply authorization context."
    ),
    "BFLA": (
        "Enforce server-side role and permission checks for every "
        "sensitive function or administrative endpoint. "
        "Deny access explicitly when the caller lacks the required role. "
        "Do not rely on UI-level hiding of admin controls."
    ),
}


# ---------------------------------------------------------------------------
# HTTP Client
# ---------------------------------------------------------------------------

def send_request(
    url: str,
    method: str,
    identity_name: str,
    timeout: float = 5.0,
    retries: int = 1,
    extra_headers: dict[str, str] | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """
    Send a single HTTP request using a simulated test identity.

    Args:
        url:            Full URL to request.
        method:         HTTP method (GET, POST, etc.).
        identity_name:  Name of the test identity (sent as X-Test-User header).
        timeout:        Per-request timeout in seconds.
        retries:        Number of retry attempts for transient failures.
        extra_headers:  Additional headers to include.
        dry_run:        If True, return a mock response without sending the request.

    Returns:
        Dict with keys: status_code, body (on success) or error (on failure).
    """
    if dry_run:
        logger.info("[DRY RUN] Would send %s %s as %s", method.upper(), url, identity_name)
        return {
            "status_code": None,
            "body": {},
            "dry_run": True,
            "url": url,
            "method": method.upper(),
            "identity": identity_name,
        }

    headers: dict[str, str] = {"X-Test-User": identity_name}
    if extra_headers:
        headers.update(extra_headers)

    last_error: str | None = None
    for attempt in range(max(1, retries + 1)):
        try:
            logger.debug(
                "Request attempt %d/%d: %s %s as %s",
                attempt + 1, retries + 1, method.upper(), url, identity_name,
            )
            resp = http_requests.request(
                method=method.upper(),
                url=url,
                headers=headers,
                timeout=timeout,
                verify=True,  # TLS verification enabled by default
                allow_redirects=True,
            )
            try:
                body = resp.json()
            except ValueError:
                body = {"raw_response": resp.text[:2000]}

            logger.debug(
                "Response: HTTP %d for %s %s", resp.status_code, method.upper(), url
            )
            return {"status_code": resp.status_code, "body": body}

        except ConnectionError as exc:
            last_error = f"Connection refused or unreachable: {exc}"
            logger.warning("Connection error (attempt %d): %s", attempt + 1, last_error)
            break  # No point retrying connection-refused

        except ReadTimeout as exc:
            last_error = f"Request timed out after {timeout}s: {exc}"
            logger.warning("Timeout (attempt %d): %s", attempt + 1, last_error)

        except RequestException as exc:
            last_error = f"Request failed: {exc}"
            logger.warning("Request error (attempt %d): %s", attempt + 1, last_error)

    return {"error": last_error or "Unknown request failure"}


# ---------------------------------------------------------------------------
# Health Check
# ---------------------------------------------------------------------------

def check_health(base_url: str, timeout: float = 5.0) -> dict[str, Any]:
    """
    Check whether the target API is reachable before scanning.

    Returns a dict with 'reachable' bool and optional 'error' message.
    """
    health_urls = [
        f"{base_url.rstrip('/')}/health",
        f"{base_url.rstrip('/')}/",
    ]
    for url in health_urls:
        try:
            resp = http_requests.get(url, timeout=timeout, verify=True)
            if resp.status_code < 500:
                return {"reachable": True, "url": url, "status_code": resp.status_code}
        except ConnectionError as exc:
            return {
                "reachable": False,
                "error": f"Connection refused — is the API running at {base_url}? ({exc})",
            }
        except RequestException as exc:
            return {"reachable": False, "error": str(exc)}
    return {"reachable": False, "error": "All health-check URLs failed."}


# ---------------------------------------------------------------------------
# Finding Builder
# ---------------------------------------------------------------------------

def build_finding(
    *,
    vuln_type: str,
    endpoint: str,
    method: str,
    test_identity: str,
    test_role: str,
    classification: dict[str, Any],
    attacker_response: dict[str, Any],
    remediation: str,
    expected_policy: str,
    endpoint_label: str = "",
) -> dict[str, Any]:
    """Build a complete, structured finding from a classification result."""
    status = classification.get("status", STATUS_INCONCLUSIVE)
    severity = classification.get("severity", "UNASSESSED")

    return {
        "finding_id": str(uuid.uuid4()),
        "vuln_type": vuln_type,
        "endpoint": endpoint,
        "method": method.upper(),
        "label": endpoint_label or endpoint,
        "test_identity": test_identity,
        "test_role": test_role,
        "expected_policy": expected_policy,
        "status": status,
        "severity": severity,
        "confidence": classification.get("confidence", "N/A"),
        "details": classification.get("details", ""),
        "http_status": attacker_response.get("status_code"),
        "evidence": _sanitize_evidence(attacker_response.get("body", {})),
        "classification_detail": {
            k: v for k, v in classification.items()
            if k not in {"status", "severity", "confidence", "details"}
        },
        "remediation": remediation,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "execution_status": "COMPLETED",
    }


def _sanitize_evidence(body: Any) -> Any:
    """
    Remove or redact sensitive fields from response evidence.
    Never include tokens, passwords, or secrets in reports.
    """
    REDACT_KEYS = {
        "password", "passwd", "secret", "token", "api_key", "apikey",
        "authorization", "auth", "credential", "private_key", "access_token",
        "refresh_token", "session",
    }
    if not isinstance(body, dict):
        return body
    return {
        k: "**REDACTED**" if k.lower() in REDACT_KEYS else v
        for k, v in body.items()
    }


# ---------------------------------------------------------------------------
# Scanner Engine
# ---------------------------------------------------------------------------

class Scanner:
    """
    Main scanning engine. Reads a validated configuration and executes
    BOLA and BFLA authorization tests against the configured endpoints.
    """

    def __init__(self, config: dict[str, Any], dry_run: bool = False):
        self.config = config
        self.dry_run = dry_run
        self.base_url: str = config["base_url"].rstrip("/")
        self.timeout: float = float(config.get("timeout", 5))
        self.retries: int = int(config.get("retries", 1))
        self.identities: dict[str, dict] = {
            ident["name"]: ident for ident in config["identities"]
        }
        self.findings: list[dict[str, Any]] = []
        self.errors: int = 0
        self.scan_status: str = "PENDING"
        self.started_at: str | None = None
        self.completed_at: str | None = None

    def _send(self, path: str, method: str, identity_name: str) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        return send_request(
            url=url,
            method=method,
            identity_name=identity_name,
            timeout=self.timeout,
            retries=self.retries,
            dry_run=self.dry_run,
        )

    def _get_identity(self, name: str) -> dict | None:
        return self.identities.get(name)

    def run(self) -> dict[str, Any]:
        """
        Execute the configured scan. Returns the complete scan result.
        """
        self.findings = []
        self.errors = 0
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.scan_status = "RUNNING"

        if not self.dry_run:
            health = check_health(self.base_url, timeout=self.timeout)
            if not health.get("reachable"):
                self.scan_status = "FAILED"
                self.completed_at = datetime.now(timezone.utc).isoformat()
                return self._build_result(
                    error_message=(
                        f"Pre-scan health check failed: {health.get('error', 'unreachable')}. "
                        "Ensure the target API is running before scanning."
                    )
                )

        endpoints: list[dict] = self.config.get("endpoints", [])
        for ep in endpoints:
            try:
                self._run_endpoint(ep)
            except Exception as exc:  # noqa: BLE001
                logger.exception("Unexpected error processing endpoint %s: %s", ep, exc)
                self.errors += 1
                self.findings.append({
                    "finding_id": str(uuid.uuid4()),
                    "vuln_type": ep.get("vuln_type", "UNKNOWN"),
                    "endpoint": ep.get("path", ""),
                    "method": ep.get("method", "GET").upper(),
                    "status": STATUS_ERROR,
                    "severity": "UNASSESSED",
                    "details": f"Unexpected scanner error: {exc}",
                    "remediation": "",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "execution_status": "ERROR",
                })

        self.completed_at = datetime.now(timezone.utc).isoformat()
        self.scan_status = (
            "COMPLETED_WITH_ERRORS" if self.errors > 0 else "COMPLETED"
        )
        return self._build_result()

    def _run_endpoint(self, ep: dict[str, Any]) -> None:
        """Dispatch to the appropriate test method based on vuln_type."""
        vuln_type = ep.get("vuln_type", "").upper()
        if vuln_type == "BOLA":
            self._run_bola(ep)
        elif vuln_type == "BFLA":
            self._run_bfla(ep)
        else:
            logger.warning("Unknown vuln_type %r for endpoint %s — skipping.", vuln_type, ep.get("path"))
            self.findings.append({
                "finding_id": str(uuid.uuid4()),
                "vuln_type": vuln_type,
                "endpoint": ep.get("path", ""),
                "method": ep.get("method", "GET").upper(),
                "status": STATUS_SKIPPED,
                "severity": "N/A",
                "details": f"Unsupported vulnerability type: {vuln_type!r}",
                "remediation": "",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "execution_status": "SKIPPED",
            })

    def _run_bola(self, ep: dict[str, Any]) -> None:
        """
        Execute a BOLA test sequence for one endpoint configuration.
        Supports multiple object IDs and (owner, attacker) identity pairs.
        """
        path_template: str = ep["path"]
        method: str = ep.get("method", "GET")
        objects: list[dict] = ep.get("objects", [])
        pairs: list[dict] = ep.get("identity_pairs", [])
        owner_id_field: str = ep.get("owner_id_field", "owner_id")
        requester_id_field: str = ep.get("requester_id_field", "requested_by")
        expected_policy: str = ep.get("expected_policy", "Only the owner can access their object.")
        label: str = ep.get("label", path_template)

        if not objects or not pairs:
            logger.warning("BOLA endpoint %s missing objects or identity_pairs — skipping.", path_template)
            return

        for obj in objects:
            obj_id = obj.get("id")
            if obj_id is None:
                continue
            path = path_template.replace("{object_id}", str(obj_id))

            for pair in pairs:
                owner_name    = pair.get("owner")
                attacker_name = pair.get("attacker")
                if not owner_name or not attacker_name:
                    continue

                owner_ident    = self._get_identity(owner_name)
                attacker_ident = self._get_identity(attacker_name)
                if owner_ident is None or attacker_ident is None:
                    logger.warning(
                        "Unknown identity in pair owner=%r attacker=%r", owner_name, attacker_name
                    )
                    continue

                logger.info(
                    "BOLA test: %s %s [owner=%s, attacker=%s, obj=%s]",
                    method.upper(), path, owner_name, attacker_name, obj_id,
                )

                owner_resp    = self._send(path, method, owner_name)
                attacker_resp = self._send(path, method, attacker_name)

                classification = classify_bola(
                    owner_response=owner_resp,
                    attacker_response=attacker_resp,
                    owner_id=owner_ident.get("id", 0),
                    attacker_id=attacker_ident.get("id", 0),
                    object_id=obj_id,
                    owner_id_field=owner_id_field,
                    requester_id_field=requester_id_field,
                )

                if classification["status"] == STATUS_ERROR:
                    self.errors += 1

                finding = build_finding(
                    vuln_type="BOLA",
                    endpoint=path,
                    method=method,
                    test_identity=attacker_name,
                    test_role=attacker_ident.get("role", "unknown"),
                    classification=classification,
                    attacker_response=attacker_resp,
                    remediation=REMEDIATION["BOLA"],
                    expected_policy=expected_policy,
                    endpoint_label=f"{label} (object {obj_id})",
                )
                self.findings.append(finding)

    def _run_bfla(self, ep: dict[str, Any]) -> None:
        """
        Execute a BFLA test sequence for one endpoint configuration.
        """
        path: str = ep["path"]
        method: str = ep.get("method", "GET")
        admin_identity_name: str = ep.get("admin_identity", "admin")
        user_identities: list[str] = ep.get("test_identities", [])
        required_role: str = ep.get("required_role", "admin")
        caller_role_field: str = ep.get("caller_role_field", "caller_role")
        required_role_field: str = ep.get("required_role_field", "required_role")
        expected_policy: str = ep.get("expected_policy", f"Only {required_role!r} role can access this endpoint.")
        label: str = ep.get("label", path)

        if not user_identities:
            logger.warning("BFLA endpoint %s missing test_identities — skipping.", path)
            return

        admin_ident = self._get_identity(admin_identity_name)
        if admin_ident is None:
            logger.warning("Admin identity %r not found — skipping BFLA test.", admin_identity_name)
            return

        logger.info("BFLA admin baseline: %s %s as %s", method.upper(), path, admin_identity_name)
        admin_resp = self._send(path, method, admin_identity_name)

        for user_name in user_identities:
            user_ident = self._get_identity(user_name)
            if user_ident is None:
                logger.warning("Test identity %r not found — skipping.", user_name)
                continue

            logger.info(
                "BFLA test: %s %s as %s (role=%s)",
                method.upper(), path, user_name, user_ident.get("role"),
            )
            user_resp = self._send(path, method, user_name)

            classification = classify_bfla(
                admin_response=admin_resp,
                user_response=user_resp,
                user_role=user_ident.get("role", "unknown"),
                required_role=required_role,
                endpoint=path,
                caller_role_field=caller_role_field,
                required_role_field=required_role_field,
            )

            if classification["status"] == STATUS_ERROR:
                self.errors += 1

            finding = build_finding(
                vuln_type="BFLA",
                endpoint=path,
                method=method,
                test_identity=user_name,
                test_role=user_ident.get("role", "unknown"),
                classification=classification,
                attacker_response=user_resp,
                remediation=REMEDIATION["BFLA"],
                expected_policy=expected_policy,
                endpoint_label=label,
            )
            self.findings.append(finding)

    def _build_result(self, error_message: str | None = None) -> dict[str, Any]:
        """Assemble the final scan result dictionary."""
        counts = _count_statuses(self.findings)
        result: dict[str, Any] = {
            "scanner_version": SCANNER_VERSION,
            "scan_status": self.scan_status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "target": self.base_url,
            "dry_run": self.dry_run,
            "summary": {
                "total_tests": len(self.findings),
                "potential_vulnerabilities": counts["POTENTIAL VULNERABILITY"],
                "not_detected": counts["NOT DETECTED"],
                "inconclusive": counts["INCONCLUSIVE"],
                "errors": counts["ERROR"] + self.errors,
                "skipped": counts["SKIPPED"],
            },
            "findings": self.findings,
        }
        if error_message:
            result["error_message"] = error_message
            result["summary"]["total_tests"] = 0
        return result


def _count_statuses(findings: list[dict]) -> dict[str, int]:
    """Count findings by status."""
    counts = {
        "POTENTIAL VULNERABILITY": 0,
        "NOT DETECTED": 0,
        "INCONCLUSIVE": 0,
        "ERROR": 0,
        "SKIPPED": 0,
    }
    for f in findings:
        status = f.get("status", "")
        if status in counts:
            counts[status] += 1
    return counts


# ---------------------------------------------------------------------------
# Legacy compatibility helpers (used by older tests)
# ---------------------------------------------------------------------------

def make_finding(
    test: str,
    detected: bool,
    details: str,
    result: dict[str, Any],
    severity: str,
    remediation: str,
) -> dict[str, Any]:
    """
    Legacy finding builder — retained for backward compatibility with
    the original three test cases.
    """
    from app.authorization_checks import STATUS_POTENTIAL, STATUS_NOT_DETECTED, SEVERITY_NONE
    return {
        "test": test,
        "status": STATUS_POTENTIAL if detected else STATUS_NOT_DETECTED,
        "severity": severity if detected else SEVERITY_NONE,
        "details": details,
        "http_status": result.get("status_code"),
        "evidence": result.get("body", {}),
        "remediation": remediation,
    }
