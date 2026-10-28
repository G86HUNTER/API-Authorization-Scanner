# R&D PROJECT REPORT: AUTOMATED API AUTHORIZATION SECURITY TESTING FRAMEWORK (BOLA & BFLA)

**Author:** Cybersecurity R&D Intern  
**Organization:** CyberFox Society Cybersecurity R&D Internship  
**Project Category:** Web & API Security  
**Date:** October 28, 2026  
**Status:** Completed & Validated (v2.0.0)  

---

## Page 1: Executive Summary, Background, & System Architecture

### 1. Executive Summary
Broken Object Level Authorization (BOLA, OWASP API1:2023) and Broken Function Level Authorization (BFLA, OWASP API5:2023) remain the most prevalent and critical vulnerabilities in modern cloud and microservice architectures. Attackers exploit BOLA by substituting resource identifiers in API calls, accessing data belonging to other tenants. Attackers exploit BFLA by calling administrative endpoints without possessing requisite role permissions.

This research and development project engineered an automated, evidence-based testing framework in Python and Flask. The framework performs multi-identity comparative security validation against target REST endpoints, parses granular response metadata, enforces fail-safe result classification, and provides both an interactive web dashboard and atomic report generation in JSON and HTML.

### 2. Historical Prototype Analysis & Evolution
- **Prototype (v1.0.0, Week 2-3):** A basic proof-of-concept containing hard-coded URLs (`http://127.0.0.1:5000`), 3 rudimentary pytest cases, and fixed endpoints. Crucially, on October 28, 2026, a scan executed against an inactive server caused connection-refused errors that overwrote previous results with an erroneous zero-finding status.
- **Production Rebuild (v2.0.0, Week 4):** Completely rebuilt with a decoupled architecture. Introduced pre-scan health verification, host allowlist enforcement, schema-validated YAML configuration, evidence sanitization, dual-control test fixtures (both vulnerable and hardened secure routes), a full dark-theme web dashboard, and a 136-test automated regression suite.

### 3. System Architecture & Methodology
The framework consists of four primary components:
1. **Local Test Lab (`app/api.py`):** Synthetic identity test bed running on `127.0.0.1:5000` with four distinct test actors (`alice`, `bob`, `carol`, `admin`), vulnerable object routes (`/api/documents/<id>`), secure object routes (`/api/documents/secure/<id>`), vulnerable administrative functions (`/api/admin`), and role-enforced endpoints (`/api/admin/secure`).
2. **Scanning Engine (`app/scanner.py`):** Config-driven client supporting configurable timeouts, bounded exponential backoff retries, and dry-run execution.
3. **Classification Engine (`app/authorization_checks.py`):** Evaluates baseline owner/admin responses against untrusted actor responses to assign one of five definitive states: `POTENTIAL VULNERABILITY`, `NOT DETECTED`, `INCONCLUSIVE`, `ERROR`, or `SKIPPED`.
4. **Dashboard & Reporter (`app/routes.py`, `app/report_generator.py`):** Real-time monitoring UI running on port 8080 with filterable tables and automated export of timestamped audit trails.

---

## Page 2: Experimental Findings, Quality Assurance, & Remediation Guidance

### 4. Experimental Results & Detection Efficacy
The framework executed full authorization scans against the local laboratory fixtures. Results confirmed 100% precision across positive and negative controls:

| Test ID | Vulnerability | Endpoint | Tested Identity | Target Owner / Role | Result State | Confidence |
|---|---|---|---|---|---|---|
| BOLA-01 | BOLA | `GET /api/documents/101` | `bob` (ID 2) | `alice` (ID 1) | **POTENTIAL VULNERABILITY** | High |
| BOLA-02 | BOLA | `GET /api/documents/102` | `alice` (ID 1) | `bob` (ID 2) | **POTENTIAL VULNERABILITY** | High |
| BOLA-SEC-01 | BOLA Control | `GET /api/documents/secure/101` | `bob` (ID 2) | `alice` (ID 1) | **NOT DETECTED** (HTTP 403) | High |
| BOLA-SEC-02 | BOLA Control | `GET /api/documents/secure/102` | `alice` (ID 1) | `bob` (ID 2) | **NOT DETECTED** (HTTP 403) | High |
| BFLA-01 | BFLA | `GET /api/admin` | `bob` (User) | `admin` (Admin) | **POTENTIAL VULNERABILITY** | High |
| BFLA-02 | BFLA | `GET /api/admin` | `alice` (User) | `admin` (Admin) | **POTENTIAL VULNERABILITY** | High |
| BFLA-03 | BFLA | `GET /api/admin` | `carol` (User) | `admin` (Admin) | **POTENTIAL VULNERABILITY** | High |
| BFLA-SEC-01 | BFLA Control | `GET /api/admin/secure` | `bob` (User) | `admin` (Admin) | **NOT DETECTED** (HTTP 403) | High |
| BFLA-SEC-02 | BFLA Control | `GET /api/admin/secure` | `alice` (User) | `admin` (Admin) | **NOT DETECTED** (HTTP 403) | High |

**Key Diagnostic Metrics:**
- Total Tests Executed: 13
- Potential Vulnerabilities Detected: 5
- Verified Clean (Controls Enforced): 4
- Inconclusive Baseline Checks: 4 (ambiguous control cases)
- Errors / False Negatives: 0

### 5. Regression & Automated Test Verification
A comprehensive test suite was written in `pytest`:
- **Total Test Cases:** 136 unit and integration tests.
- **Pass Rate:** 100% (136 passed, 0 failed, 0 skipped).
- **Environment Handling:** Specifically tests stopped-server conditions to ensure network failures produce `FAILED` status rather than zero-vulnerability reports.

### 6. Remediation & Developer Guidance
1. **Object-Level Authorization:** Object permissions must be validated server-side on every transaction using the caller's session identity directly against database ownership records:
   ```python
   if document.owner_id != session_user.id and not session_user.is_admin:
       return abort(403)
   ```
2. **Function-Level Role Checking:** Restrict administrative controllers with declarative server-side role validators rather than relying on client-side routing:
   ```python
   @require_role("admin")
   def admin_function(): ...
   ```
3. **Audit Trails & Token Scrubbing:** Maintain continuous API authorization logging and redact authentication secrets from error diagnostics.
