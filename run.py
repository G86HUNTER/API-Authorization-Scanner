"""
run.py — Application entry point.

Usage (from project root):
    python run.py            — Start the dashboard application
    python run.py --api      — Start the local test lab API only
    python run.py --scan     — Run a CLI scan against the configured target
    python run.py --dry-run  — Show what the scanner would do (no requests sent)
"""

import argparse
import logging
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Configure logging before any imports that use logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("run")

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))


def run_api():
    """Start the local test lab Flask API on 127.0.0.1:5000."""
    from app.api import app
    logger.info("Starting local test lab API at http://127.0.0.1:5000")
    logger.info("WARNING: For authorized local testing only.")
    app.run(host="127.0.0.1", port=5000, debug=False)


def run_dashboard():
    """Start the dashboard application on 127.0.0.1:8080."""
    from app.routes import create_app
    dashboard = create_app()
    logger.info("Starting dashboard at http://127.0.0.1:8080")
    dashboard.run(host="127.0.0.1", port=8080, debug=False)


def run_scan(dry_run: bool = False):
    """Run a CLI scan against the configured target."""
    import json
    from app.config import get_default_config_path, load_config, ConfigError
    from app.scanner import Scanner
    from app.report_generator import generate_json_report, generate_html_report

    config_path = get_default_config_path()
    logger.info("Loading configuration from: %s", config_path)

    try:
        cfg = load_config(config_path)
    except ConfigError as exc:
        logger.error("Configuration error: %s", exc)
        sys.exit(1)

    reports_dir = PROJECT_ROOT / "reports"

    logger.info("Target: %s", cfg["base_url"])
    logger.info("Dry run: %s", dry_run)
    logger.info("Starting scan...")

    scanner = Scanner(cfg, dry_run=dry_run)
    result = scanner.run()

    # Summary
    summary = result.get("summary", {})
    print("\n" + "=" * 55)
    print("  API Authorization Security Scanner — Results")
    print("=" * 55)
    print(f"  Scan status:              {result.get('scan_status', 'UNKNOWN')}")
    print(f"  Target:                   {result.get('target', 'N/A')}")
    print(f"  Total tests:              {summary.get('total_tests', 0)}")
    print(f"  Potential vulnerabilities:{summary.get('potential_vulnerabilities', 0)}")
    print(f"  Not detected:             {summary.get('not_detected', 0)}")
    print(f"  Inconclusive:             {summary.get('inconclusive', 0)}")
    print(f"  Errors:                   {summary.get('errors', 0)}")
    print(f"  Skipped:                  {summary.get('skipped', 0)}")
    print("=" * 55)

    if result.get("error_message"):
        print(f"\nERROR: {result['error_message']}")

    for finding in result.get("findings", []):
        status   = finding.get("status", "")
        vuln     = finding.get("vuln_type", "")
        endpoint = finding.get("endpoint", "")
        method   = finding.get("method", "")
        severity = finding.get("severity", "")
        print(f"\n  [{status}] {vuln} — {method} {endpoint}")
        print(f"    Severity:   {severity}")
        print(f"    Confidence: {finding.get('confidence', 'N/A')}")
        print(f"    Details:    {finding.get('details', '')[:120]}")

    if not dry_run:
        json_path = generate_json_report(result, reports_dir, filename="authorization_scan.json")
        html_path = generate_html_report(result, reports_dir, filename="authorization_scan.html")
        ts_json   = generate_json_report(result, reports_dir)
        ts_html   = generate_html_report(result, reports_dir)
        print(f"\n  JSON report: {json_path}")
        print(f"  HTML report: {html_path}")
        print(f"  Timestamped: {ts_json.name}, {ts_html.name}")

    # Exit with non-zero if scan failed
    if result.get("scan_status") == "FAILED":
        sys.exit(2)


def main():
    parser = argparse.ArgumentParser(
        description="API Authorization Security Testing Framework"
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--api", action="store_true",
        help="Start the local test lab API (port 5000)"
    )
    group.add_argument(
        "--scan", action="store_true",
        help="Run a CLI scan against the configured target"
    )
    group.add_argument(
        "--dry-run", action="store_true",
        help="Show what the scanner would do without sending requests"
    )
    args = parser.parse_args()

    if args.api:
        run_api()
    elif args.scan:
        run_scan(dry_run=False)
    elif args.dry_run:
        run_scan(dry_run=True)
    else:
        run_dashboard()


if __name__ == "__main__":
    main()
