# API Authorization Security Testing Framework

> **Authorized use only.** This framework is designed for security testing against systems you are explicitly authorized to test. The default configuration targets `127.0.0.1` (localhost) only.

---

## Project Overview

A configurable security-testing framework that helps authorized penetration testers and developers identify potential authorization weaknesses in REST APIs:

- **BOLA** — Broken Object Level Authorization (OWASP API Security #1)
- **BFLA** — Broken Function Level Authorization (OWASP API Security #5)

The framework tests authorization behavior using controlled requests, multiple test identities, response comparison, evidence collection, and structured reporting. It supports a functional web dashboard and CLI operation.

---

## Supported Checks

| Check | Description | Result States |
|-------|-------------|---------------|
| BOLA  | Cross-user object access — can user B access user A's resource? | POTENTIAL VULNERABILITY / NOT DETECTED / INCONCLUSIVE / ERROR |
| BFLA  | Function-level privilege escalation — can a normal user call admin functions? | POTENTIAL VULNERABILITY / NOT DETECTED / INCONCLUSIVE / ERROR |

---

## Architecture

```
API-Authorization-Scanner/
├── app/
│   ├── __init__.py          # Package init
│   ├── api.py               # Local test lab (vulnerable + secure fixtures)
│   ├── authorization_checks.py  # BOLA/BFLA classification logic
│   ├── config.py            # YAML config loader + validator
│   ├── report_generator.py  # JSON + HTML report generation
│   ├── routes.py            # Dashboard Flask backend
│   └── scanner.py           # Core scanning engine
├── config/
│   └── scan_config.yaml     # Scan configuration (edit to customize targets)
├── dashboard/
│   ├── templates/
│   │   └── dashboard.html   # Dashboard HTML template
│   └── static/
│       ├── css/dashboard.css
│       └── js/dashboard.js
├── tests/
│   ├── conftest.py
│   ├── test_scanner.py      # Scanner unit tests
│   ├── test_bola.py         # BOLA classification tests
│   ├── test_bfla.py         # BFLA classification tests
│   ├── test_config.py       # Configuration tests
│   ├── test_reports.py      # Report generation tests
│   ├── test_api.py          # Local lab API tests
│   ├── test_routes.py       # Dashboard routes tests
│   └── test_integration.py  # Full integration tests
├── reports/                 # Security Scan Reports
│   ├── authorization_scan.json # Comprehensive findings (JSON)
│   ├── authorization_scan.html # Interactive visual report (HTML)
│   └── initial_scan.json    # Baseline comparison report
├── docs/                    # Internship & Architecture Documentation
│   ├── architecture.md      # Architecture & system flow diagrams
│   ├── user_guide.md        # CLI & Dashboard operator guide
│   ├── testing.md           # 136-test QA verification suite
│   ├── limitations.md       # Ethical boundaries & technical limits
│   ├── PROJECT_REPORT.md    # 2-Page Formal Internship Project Report
│   ├── PRESENTATION_SLIDES.md # 5-Slide PowerPoint presentation outline
│   ├── presentation.pptx    # Complete 16:9 5-Slide PowerPoint Deck
│   └── screenshots/         # Captured test execution & evidence screenshots
├── run.py                   # Application entry point
├── upload_to_github.ps1     # Automated GitHub upload script
├── requirements.txt
├── .gitignore
└── README.md
```

---

## Installation (Windows PowerShell)

### 1. Prerequisites

- Python 3.11 or later ([python.org](https://www.python.org/downloads/))
- Git ([git-scm.com](https://git-scm.com/))

Verify:
```powershell
python --version
git --version
```

### 2. Clone or Navigate to the Project

```powershell
cd d:\Cyberfox\API-Authorization-Scanner
```

### 3. Create a Virtual Environment

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

> If you see an execution policy error, run: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`

### 4. Install Dependencies

```powershell
pip install -r requirements.txt
```

---

## Running the Application

You need **two terminal windows**.

### Terminal 1 — Start the Local Test Lab API

```powershell
.venv\Scripts\Activate.ps1
python run.py --api
```

The lab API starts at `http://127.0.0.1:5000`. It provides intentionally vulnerable and secure test endpoints.

### Terminal 2 — Start the Dashboard

```powershell
.venv\Scripts\Activate.ps1
python run.py
```

Open `http://127.0.0.1:8080` in your browser.

---

## Running a Scan

### From the Dashboard

1. Ensure the lab API is running (Terminal 1 above).
2. Open `http://127.0.0.1:8080`.
3. Click **Run Scan** in the sidebar.
4. Click **Start Scan**.
5. Watch the progress — results appear in **Findings** after completion.
6. Download JSON or HTML reports from **Reports**.

### From the CLI

```powershell
# Run a full scan
python run.py --scan

# Dry run (shows what would be tested, no requests sent)
python run.py --dry-run
```

---

## Running Tests

```powershell
# Unit tests only (no running server required)
pytest tests/ -v --ignore=tests/test_integration.py

# All tests including integration (requires lab API on port 5099 — auto-started)
pytest tests/ -v

# With coverage report
pytest tests/ -v --cov=app --cov-report=term-missing

# Specific test module
pytest tests/test_bola.py -v
pytest tests/test_bfla.py -v
```

---

## Configuration

Edit `config/scan_config.yaml` to customize:

- **`base_url`** — Target API base URL (must be in `allowed_hosts`)
- **`allowed_hosts`** — Allowlist of permitted hostnames (localhost only by default)
- **`identities`** — Test user accounts (local lab identities)
- **`endpoints`** — Endpoints to test, with BOLA/BFLA parameters
- **`timeout`** — Request timeout in seconds
- **`retries`** — Retry count for transient failures

> **Security:** Never add external hostnames to `allowed_hosts` without authorization. Never commit real credentials to configuration files.

---

## Reports

Reports are saved to `reports/`:

- `authorization_scan.json` — Latest JSON report (overwrites on each scan)
- `authorization_scan.html` — Latest HTML report
- `scan_<timestamp>.json/html` — Timestamped copies (preserved)

> A failed scan (connection error) produces a `FAILED` status report, not a clean zero-findings report.

---

## GitHub

**Repository:** https://github.com/G86HUNTER

This project was built independently as a clean implementation based on the author's previous prototype. The existing `.venv` and early scanner code from the Desktop project were inspected and their patterns preserved (test identity structure, remediation text, finding format), but the full implementation was rebuilt from scratch with a complete scanning engine, dashboard, test suite, and report generation.

**Git workflow:**

```powershell
git init
git add .
git commit -m "feat: complete BOLA/BFLA scanner framework v2.0.0"
# Push only after review:
# git remote add origin https://github.com/G86HUNTER/<repo>.git
# git push -u origin main
```

---

## Ethical Testing Boundaries

- This framework targets `127.0.0.1` (localhost) by default.
- Adding external targets requires explicit configuration and authorization.
- All test data uses synthetic identities — no real user data.
- The intentionally vulnerable endpoints are clearly labeled in source code.
- This tool is for authorized security testing only — not for unauthorized access.
- Results are preliminary estimates, not confirmed production vulnerabilities.

---

## Known Limitations

1. **BOLA detection** requires that the API returns ownership metadata (e.g., `owner_id`, `requested_by`) in the response body. APIs without these fields produce INCONCLUSIVE results.
2. **BFLA detection** requires that the API returns role metadata or explicit denial responses. APIs returning generic 200 responses without role context may produce INCONCLUSIVE results.
3. No automatic endpoint discovery — all endpoints must be configured explicitly.
4. No OpenAPI/Swagger parsing in v2.0.0 (planned enhancement).
5. No authentication token support — uses `X-Test-User` header (local lab convention).
6. Severity estimates are preliminary — full CVSS scoring is not implemented.
7. Single-threaded scanning — concurrent scanning is not implemented.
8. Not designed for external/internet-facing APIs without manual configuration.

---

## Changelog

### v2.0.0 (2026-10-28)
- Complete rebuild with full scanning engine
- BOLA/BFLA classification with confidence levels and five result states
- Vulnerable and secure test fixtures for false-positive validation
- Functional web dashboard (dark theme)
- JSON and HTML report generation with atomic writes
- Pre-scan health check (fixes connection-refused false-clean regression)
- Comprehensive pytest suite (60+ tests)
- YAML configuration with full validation
- CLI and dashboard operation
- Security controls: allowlist, scheme validation, secret redaction

### v1.0.0 (2026-10-21)
- Initial prototype: two-request scanner, three passing tests
