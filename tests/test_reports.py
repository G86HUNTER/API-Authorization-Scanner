"""
Report generation tests.
"""

from __future__ import annotations

import json
import pytest
from pathlib import Path

from app.report_generator import (
    generate_json_report,
    generate_html_report,
    list_reports,
)


SAMPLE_RESULT = {
    "scanner_version": "2.0.0",
    "scan_status":     "COMPLETED",
    "started_at":      "2026-10-28T17:00:00+00:00",
    "completed_at":    "2026-10-28T17:00:05+00:00",
    "target":          "http://127.0.0.1:5000",
    "dry_run":         False,
    "summary": {
        "total_tests":              4,
        "potential_vulnerabilities": 2,
        "not_detected":             1,
        "inconclusive":             0,
        "errors":                   0,
        "skipped":                  1,
    },
    "findings": [
        {
            "finding_id":     "aaaa-1111",
            "vuln_type":      "BOLA",
            "endpoint":       "/api/documents/101",
            "method":         "GET",
            "test_identity":  "bob",
            "test_role":      "user",
            "expected_policy": "Owner-only access.",
            "status":         "POTENTIAL VULNERABILITY",
            "severity":       "High",
            "confidence":     "High",
            "details":        "Bob accessed Alice's document.",
            "http_status":    200,
            "evidence":       {"owner_id": 1, "requested_by": 2},
            "classification_detail": {},
            "remediation":    "Enforce ownership checks.",
            "timestamp":      "2026-10-28T17:00:01+00:00",
            "execution_status": "COMPLETED",
        },
    ],
}


class TestJsonReport:

    def test_json_report_created(self, tmp_path):
        path = generate_json_report(SAMPLE_RESULT, tmp_path, "test_report.json")
        assert path.exists()
        assert path.suffix == ".json"

    def test_json_report_contents(self, tmp_path):
        path = generate_json_report(SAMPLE_RESULT, tmp_path, "test_report.json")
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["project"] == "API Authorization Security Testing Framework"
        assert data["scan_status"] == "COMPLETED"
        assert len(data["findings"]) == 1
        assert data["summary"]["total_tests"] == 4

    def test_json_report_includes_limitations(self, tmp_path):
        path = generate_json_report(SAMPLE_RESULT, tmp_path)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert "limitations" in data

    def test_json_report_timestamped_by_default(self, tmp_path):
        path = generate_json_report(SAMPLE_RESULT, tmp_path)
        assert path.name.startswith("scan_")
        assert path.suffix == ".json"

    def test_json_report_not_in_tmp_path(self, tmp_path):
        """No report file should exist before generation."""
        reports = list(tmp_path.glob("*.json"))
        assert reports == []

    def test_json_report_creates_output_dir(self, tmp_path):
        nested = tmp_path / "nested" / "reports"
        path = generate_json_report(SAMPLE_RESULT, nested, "test.json")
        assert path.exists()

    def test_json_report_accurate_summary(self, tmp_path):
        path = generate_json_report(SAMPLE_RESULT, tmp_path, "test.json")
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["summary"]["potential_vulnerabilities"] == 2
        assert data["summary"]["not_detected"]             == 1

    def test_failed_scan_report_contains_error(self, tmp_path):
        failed = dict(SAMPLE_RESULT)
        failed["scan_status"]   = "FAILED"
        failed["error_message"] = "Connection refused."
        path = generate_json_report(failed, tmp_path, "failed.json")
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["scan_status"]   == "FAILED"
        assert "error_message"       in data


class TestHtmlReport:

    def test_html_report_created(self, tmp_path):
        path = generate_html_report(SAMPLE_RESULT, tmp_path, "test_report.html")
        assert path.exists()
        assert path.suffix == ".html"

    def test_html_report_contains_project_name(self, tmp_path):
        path = generate_html_report(SAMPLE_RESULT, tmp_path, "test.html")
        html = path.read_text(encoding="utf-8")
        assert "API Authorization Security Testing Framework" in html

    def test_html_report_contains_findings(self, tmp_path):
        path = generate_html_report(SAMPLE_RESULT, tmp_path, "test.html")
        html = path.read_text(encoding="utf-8")
        assert "BOLA" in html
        assert "Bob accessed" in html

    def test_html_report_contains_limitations_warning(self, tmp_path):
        path = generate_html_report(SAMPLE_RESULT, tmp_path, "test.html")
        html = path.read_text(encoding="utf-8")
        assert "Limitations" in html

    def test_html_report_shows_scan_status(self, tmp_path):
        path = generate_html_report(SAMPLE_RESULT, tmp_path, "test.html")
        html = path.read_text(encoding="utf-8")
        assert "COMPLETED" in html

    def test_html_report_timestamps(self, tmp_path):
        path = generate_html_report(SAMPLE_RESULT, tmp_path)
        assert path.name.startswith("scan_")
        assert path.suffix == ".html"

    def test_html_report_failed_scan_shows_error(self, tmp_path):
        failed = dict(SAMPLE_RESULT)
        failed["scan_status"]   = "FAILED"
        failed["error_message"] = "Connection refused — API not running."
        path = generate_html_report(failed, tmp_path, "failed.html")
        html = path.read_text(encoding="utf-8")
        assert "FAILED" in html
        assert "Connection refused" in html


class TestListReports:

    def test_empty_directory_returns_empty_list(self, tmp_path):
        result = list_reports(tmp_path)
        assert result == []

    def test_nonexistent_directory_returns_empty_list(self, tmp_path):
        result = list_reports(tmp_path / "nonexistent")
        assert result == []

    def test_lists_json_and_html_files(self, tmp_path):
        (tmp_path / "scan1.json").write_text("{}", encoding="utf-8")
        (tmp_path / "scan1.html").write_text("<html></html>", encoding="utf-8")
        result = list_reports(tmp_path)
        names = [r["filename"] for r in result]
        assert "scan1.json" in names
        assert "scan1.html" in names

    def test_report_metadata_includes_size_and_modified(self, tmp_path):
        (tmp_path / "scan1.json").write_text('{"test": true}', encoding="utf-8")
        result = list_reports(tmp_path)
        r = next(r for r in result if r["filename"] == "scan1.json")
        assert r["size_bytes"] > 0
        assert r["modified"]
        assert r["type"] == "JSON"
