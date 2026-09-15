"""Tests for report generation."""
from pathlib import Path

import pytest

from app import create_app
from app.config import TestingConfig
from app.extensions import db
from app.models.finding import Finding
from app.models.scan import Scan
from app.services.orchestrator import run_scan
from app.services.reporting import (
    build_report_data,
    render_csv,
    render_html,
    render_pdf,
)


@pytest.fixture()
def app():
    app = create_app(TestingConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def scanned(app, tmp_path):
    (tmp_path / ".env").write_text(
        'AWS_ACCESS_KEY_ID="AKIA' + "A" * 16 + '"\n'
        'AWS_SECRET_ACCESS_KEY="' + "a" * 40 + '"\n'
        'password = "S3cr3tP@ssw0rd!12345"\n',
        encoding="utf-8",
    )
    result = run_scan(
        scan_name="report-test",
        source_type="directory",
        source_path=str(tmp_path),
    )
    scan = db.session.get(Scan, result.scan_id)
    findings = db.session.query(Finding).filter_by(scan_id=result.scan_id).all()
    return scan, findings


def test_build_report_data_shape(scanned):
    scan, findings = scanned
    data = build_report_data(scan, findings)
    assert set(data.keys()) == {"report", "scan", "summary", "findings"}
    assert data["report"]["product"] == "CloudGuard"
    assert data["scan"]["id"] == scan.id
    assert data["summary"]["total"] == len(findings)


def test_report_data_severity_breakdown(scanned):
    scan, findings = scanned
    data = build_report_data(scan, findings)
    for sev in ("critical", "high", "medium", "low", "informational"):
        assert sev in data["summary"]["by_severity"]


def test_report_data_findings_redacted(scanned):
    scan, findings = scanned
    data = build_report_data(scan, findings)
    for f in data["findings"]:
        assert "AKIA" + "A" * 16 not in (f["redacted_value"] or "")
        assert "a" * 40 not in (f["redacted_value"] or "")
        assert f["fingerprint"]
        assert len(f["fingerprint"]) == 64


def test_report_data_never_contains_plaintext(scanned):
    scan, findings = scanned
    data = build_report_data(scan, findings)
    import json as _json
    blob = _json.dumps(data)
    assert "AKIA" + "A" * 16 not in blob
    assert "a" * 40 not in blob
    assert "S3cr3tP@ssw0rd!12345" not in blob


def test_report_data_findings_sorted_by_severity(scanned):
    scan, findings = scanned
    data = build_report_data(scan, findings)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    ranks = [order.get(f["severity"], 5) for f in data["findings"]]
    assert ranks == sorted(ranks)


def test_csv_has_header_and_rows(scanned):
    scan, findings = scanned
    data = build_report_data(scan, findings)
    csv_text = render_csv(data)
    lines = csv_text.strip().splitlines()
    assert lines[0].startswith("id,severity,risk_score,secret_type")
    assert len(lines) == 1 + len(findings)


def test_csv_neutralizes_formula_injection(scanned):
    scan, findings = scanned
    data = build_report_data(scan, findings)
    # inject a fake row to ensure neutralization works
    data["findings"].append({
        "id": 9999,
        "severity": "low",
        "risk_score": 10.0,
        "secret_type": "=cmd|' /C calc'!A0",
        "file_path": "x.py",
        "line_number": 1,
        "column_number": 1,
        "redacted_value": "@evil",
        "fingerprint": "f" * 64,
        "confidence": 0.5,
        "validation_status": "unknown",
        "triage_status": "open",
        "detection_reason": "test",
    })
    csv_text = render_csv(data)
    assert "'=cmd|" in csv_text
    assert "'@evil" in csv_text


def test_csv_redacts_values(scanned):
    scan, findings = scanned
    data = build_report_data(scan, findings)
    csv_text = render_csv(data)
    assert "AKIA" + "A" * 16 not in csv_text
    assert "a" * 40 not in csv_text


def test_html_is_full_document(scanned):
    scan, findings = scanned
    data = build_report_data(scan, findings)
    html = render_html(data)
    assert html.startswith("<!doctype html>")
    assert "</html>" in html
    assert scan.scan_name in html
    assert "CloudGuard Security Report" in html


def test_html_redacts_secrets(scanned):
    scan, findings = scanned
    data = build_report_data(scan, findings)
    html = render_html(data)
    assert "AKIA" + "A" * 16 not in html
    assert "a" * 40 not in html
    assert "S3cr3tP@ssw0rd!12345" not in html


def test_html_escapes_hostile_strings(scanned):
    scan, findings = scanned
    data = build_report_data(scan, findings)
    data["scan"]["name"] = "<script>alert(1)</script>"
    html = render_html(data)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_pdf_returns_bytes(scanned):
    scan, findings = scanned
    data = build_report_data(scan, findings)
    pdf = render_pdf(data)
    assert isinstance(pdf, bytes)
    assert pdf.startswith(b"%PDF")


def test_pdf_does_not_contain_plaintext(scanned):
    scan, findings = scanned
    data = build_report_data(scan, findings)
    pdf = render_pdf(data)
    assert b"AKIA" + b"A" * 16 not in pdf


def test_empty_scan_renders_without_error(app):
    scan = Scan(scan_name="empty", source_type="directory", status="completed")
    db.session.add(scan)
    db.session.commit()
    data = build_report_data(scan, [])
    assert data["summary"]["total"] == 0
    assert render_csv(data).strip().splitlines()[0].startswith("id,severity")
    assert "CloudGuard Security Report" in render_html(data)
    assert render_pdf(data).startswith(b"%PDF")