"""
Report generation — JSON and HTML output from scan results.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCANNER_VERSION = "2.0.0"
PROJECT_NAME = "API Authorization Security Testing Framework"


def _status_badge_html(status: str) -> str:
    colors = {
        "POTENTIAL VULNERABILITY": "#e53e3e",
        "NOT DETECTED":            "#38a169",
        "INCONCLUSIVE":            "#d69e2e",
        "ERROR":                   "#e53e3e",
        "SKIPPED":                 "#718096",
    }
    color = colors.get(status, "#718096")
    return f'<span class="badge" style="background:{color}">{status}</span>'


def _severity_badge_html(severity: str) -> str:
    colors = {
        "High":        "#e53e3e",
        "Medium":      "#d69e2e",
        "Low":         "#3182ce",
        "UNCONFIRMED": "#718096",
        "UNASSESSED":  "#718096",
        "N/A":         "#718096",
    }
    color = colors.get(severity, "#718096")
    return f'<span class="badge" style="background:{color}">{severity}</span>'


def generate_json_report(
    scan_result: dict[str, Any],
    output_dir: str | Path,
    filename: str | None = None,
) -> Path:
    """
    Generate a JSON report from a scan result.

    Args:
        scan_result:  The result dict returned by Scanner.run().
        output_dir:   Directory in which to write the report.
        filename:     Optional explicit filename (default: timestamped name).

    Returns:
        Path to the generated report file.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if filename is None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        filename = f"scan_{ts}.json"

    report = _build_report_envelope(scan_result)
    report_path = output_dir / filename

    # Atomic write: write to temp file first, then rename
    tmp_path = report_path.with_suffix(".tmp")
    tmp_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    tmp_path.replace(report_path)

    return report_path


def generate_html_report(
    scan_result: dict[str, Any],
    output_dir: str | Path,
    filename: str | None = None,
) -> Path:
    """
    Generate a human-readable HTML report from a scan result.

    Args:
        scan_result:  The result dict returned by Scanner.run().
        output_dir:   Directory in which to write the report.
        filename:     Optional explicit filename.

    Returns:
        Path to the generated report file.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if filename is None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        filename = f"scan_{ts}.html"

    report = _build_report_envelope(scan_result)
    html = _render_html(report)

    report_path = output_dir / filename
    tmp_path = report_path.with_suffix(".tmp")
    tmp_path.write_text(html, encoding="utf-8")
    tmp_path.replace(report_path)

    return report_path


def _build_report_envelope(scan_result: dict[str, Any]) -> dict[str, Any]:
    """Wrap scan result in a full report envelope."""
    return {
        "project": PROJECT_NAME,
        "scanner_version": SCANNER_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "limitations": (
            "This tool tests against intentionally vulnerable local fixtures only. "
            "Findings are preliminary estimates — not confirmed production vulnerabilities. "
            "Manual validation by a qualified security professional is required."
        ),
        "scope": "Local test lab — 127.0.0.1 only by default.",
        **scan_result,
    }


def _render_html(report: dict[str, Any]) -> str:
    """Render the full HTML report string."""
    summary = report.get("summary", {})
    findings = report.get("findings", [])
    scan_status = report.get("scan_status", "UNKNOWN")
    error_msg = report.get("error_message", "")

    status_color = {
        "COMPLETED":             "#38a169",
        "COMPLETED_WITH_ERRORS": "#d69e2e",
        "FAILED":                "#e53e3e",
        "RUNNING":               "#3182ce",
        "PENDING":               "#718096",
    }.get(scan_status, "#718096")

    findings_html = ""
    if findings:
        for f in findings:
            evidence_str = json.dumps(f.get("evidence", {}), indent=2)
            classification_str = json.dumps(f.get("classification_detail", {}), indent=2)
            findings_html += f"""
            <div class="finding-card">
                <div class="finding-header">
                    <span class="vuln-type">{f.get('vuln_type','')}</span>
                    {_status_badge_html(f.get('status',''))}
                    {_severity_badge_html(f.get('severity',''))}
                    <span class="confidence">Confidence: {f.get('confidence','N/A')}</span>
                </div>
                <table class="finding-table">
                    <tr><td>Finding ID</td><td><code>{f.get('finding_id','')}</code></td></tr>
                    <tr><td>Endpoint</td><td><code>{f.get('method','')} {f.get('endpoint','')}</code></td></tr>
                    <tr><td>Test Identity</td><td>{f.get('test_identity','')} (role: {f.get('test_role','')})</td></tr>
                    <tr><td>Expected Policy</td><td>{f.get('expected_policy','')}</td></tr>
                    <tr><td>HTTP Status</td><td>{f.get('http_status','N/A')}</td></tr>
                    <tr><td>Timestamp</td><td>{f.get('timestamp','')}</td></tr>
                </table>
                <div class="section-label">Details</div>
                <p>{f.get('details','')}</p>
                <div class="section-label">Evidence</div>
                <pre><code>{evidence_str}</code></pre>
                <div class="section-label">Classification Detail</div>
                <pre><code>{classification_str}</code></pre>
                <div class="section-label">Remediation</div>
                <p class="remediation">{f.get('remediation','')}</p>
            </div>"""
    else:
        findings_html = '<p class="no-findings">No findings recorded for this scan.</p>'

    error_html = f'<div class="alert alert-error"><strong>Scan Error:</strong> {error_msg}</div>' if error_msg else ""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{report['project']} — Scan Report</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 2rem; }}
  h1 {{ font-size: 1.8rem; color: #58a6ff; margin-bottom: .25rem; }}
  h2 {{ font-size: 1.2rem; color: #58a6ff; margin: 2rem 0 1rem; border-bottom: 1px solid #30363d; padding-bottom: .5rem; }}
  .meta {{ color: #8b949e; font-size: .85rem; margin-bottom: 1.5rem; }}
  .meta span {{ margin-right: 1.5rem; }}
  .scan-status {{ display:inline-block; padding:.3rem .8rem; border-radius:4px; font-weight:600; font-size:.85rem; background:{status_color}22; color:{status_color}; border:1px solid {status_color}; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 1rem; margin: 1rem 0 2rem; }}
  .summary-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem; text-align: center; }}
  .summary-card .num {{ font-size: 2rem; font-weight: 700; }}
  .summary-card .label {{ font-size: .75rem; color: #8b949e; text-transform: uppercase; letter-spacing: .05em; }}
  .vuln   {{ color: #e53e3e; }}
  .safe   {{ color: #38a169; }}
  .warn   {{ color: #d69e2e; }}
  .info   {{ color: #3182ce; }}
  .grey   {{ color: #718096; }}
  .finding-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }}
  .finding-header {{ display: flex; align-items: center; gap: .75rem; flex-wrap: wrap; margin-bottom: 1rem; }}
  .vuln-type {{ font-weight: 700; font-size: 1.1rem; color: #e2e8f0; }}
  .badge {{ display:inline-block; padding:.2rem .7rem; border-radius:4px; color:#fff; font-size:.75rem; font-weight:600; }}
  .confidence {{ font-size:.8rem; color:#8b949e; margin-left:auto; }}
  .finding-table {{ width: 100%; border-collapse: collapse; margin-bottom: 1rem; font-size: .85rem; }}
  .finding-table td {{ padding: .4rem .75rem; border-bottom: 1px solid #21262d; vertical-align: top; }}
  .finding-table td:first-child {{ color: #8b949e; width: 160px; white-space: nowrap; }}
  .section-label {{ font-size: .7rem; text-transform: uppercase; letter-spacing: .08em; color: #58a6ff; margin: 1rem 0 .25rem; }}
  pre {{ background: #0d1117; border: 1px solid #21262d; border-radius: 4px; padding: .75rem; overflow-x: auto; font-size: .8rem; }}
  code {{ font-family: 'Consolas', 'Courier New', monospace; }}
  .remediation {{ color: #63b3ed; font-size:.9rem; }}
  .no-findings {{ color: #8b949e; font-style: italic; }}
  .alert-error {{ background: #e53e3e22; border: 1px solid #e53e3e; border-radius: 6px; padding: 1rem; color: #fc8181; margin-bottom: 1rem; }}
  .limitations {{ background: #d69e2e18; border: 1px solid #d69e2e; border-radius: 6px; padding: 1rem; margin: 1.5rem 0; font-size: .85rem; color: #fbd38d; }}
  p {{ margin: .5rem 0; }}
</style>
</head>
<body>
<div class="container">
  <h1>🔒 {report['project']}</h1>
  <div class="meta">
    <span>Scanner v{report['scanner_version']}</span>
    <span>Generated: {report['generated_at']}</span>
    <span>Target: {report.get('target', 'N/A')}</span>
    <span class="scan-status">{scan_status}</span>
  </div>

  <div class="limitations">
    ⚠️ <strong>Limitations:</strong> {report['limitations']}
  </div>

  {error_html}

  <h2>Scan Summary</h2>
  <div class="summary-grid">
    <div class="summary-card"><div class="num">{summary.get('total_tests',0)}</div><div class="label">Total Tests</div></div>
    <div class="summary-card"><div class="num vuln">{summary.get('potential_vulnerabilities',0)}</div><div class="label">Potential Vulns</div></div>
    <div class="summary-card"><div class="num safe">{summary.get('not_detected',0)}</div><div class="label">Not Detected</div></div>
    <div class="summary-card"><div class="num warn">{summary.get('inconclusive',0)}</div><div class="label">Inconclusive</div></div>
    <div class="summary-card"><div class="num vuln">{summary.get('errors',0)}</div><div class="label">Errors</div></div>
    <div class="summary-card"><div class="num grey">{summary.get('skipped',0)}</div><div class="label">Skipped</div></div>
  </div>

  <h2>Findings</h2>
  {findings_html}

  <div class="meta" style="margin-top:2rem; padding-top:1rem; border-top:1px solid #30363d;">
    Scope: {report.get('scope', 'N/A')} &nbsp;|&nbsp;
    Started: {report.get('started_at', 'N/A')} &nbsp;|&nbsp;
    Completed: {report.get('completed_at', 'N/A')}
  </div>
</div>
</body>
</html>"""


def list_reports(output_dir: str | Path) -> list[dict[str, Any]]:
    """
    List available report files in the reports directory.

    Returns a list of dicts with filename, path, size, and mtime.
    """
    output_dir = Path(output_dir)
    if not output_dir.exists():
        return []

    reports = []
    for ext in ("*.json", "*.html"):
        for f in sorted(output_dir.glob(ext), key=lambda p: p.stat().st_mtime, reverse=True):
            stat = f.stat()
            reports.append({
                "filename": f.name,
                "path": str(f),
                "size_bytes": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                "type": f.suffix.lstrip(".").upper(),
            })
    return reports
