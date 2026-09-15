"""End-to-end integration tests for the scan pipeline.

Covers: scanner → detector → validator → risk → remediation → redactor →
fingerprint → DB → alerts → summary.
"""
import zipfile
from pathlib import Path

import pytest

from app import create_app
from app.config import TestingConfig
from app.extensions import db
from app.models.alert import Alert
from app.models.finding import Finding
from app.models.scan import Scan
from app.services.orchestrator import run_scan


@pytest.fixture()
def app():
    app = create_app(TestingConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def sample_project(tmp_path):
    """Create a safe test project with fake secrets."""
    (tmp_path / "src").mkdir()
    (tmp_path / ".env").write_text(
        'AWS_ACCESS_KEY_ID="AKIA' + "A" * 16 + '"\n'
        'AWS_SECRET_ACCESS_KEY="' + "a" * 40 + '"\n',
        encoding="utf-8",
    )
    (tmp_path / "src" / "app.py").write_text(
        'DATABASE_URL = "postgresql://user:pass@host:5432/db"\n'
        'password = "S3cr3tP@ssw0rd!12345"\n',
        encoding="utf-8",
    )
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_settings.py").write_text(
        'api_key = "YOUR_API_KEY_HERE"\n'
        'password = os.getenv("DATABASE_PASSWORD")\n',
        encoding="utf-8",
    )
    (tmp_path / "README.md").write_text(
        "# Project\nNothing secret here.\n",
        encoding="utf-8",
    )
    return tmp_path


def test_scan_directory_creates_scan_row(app, sample_project):
    result = run_scan(
        scan_name="first",
        source_type="directory",
        source_path=str(sample_project),
    )
    assert result.status == "completed"
    scan = db.session.get(Scan, result.scan_id)
    assert scan is not None
    assert scan.status == "completed"
    assert scan.files_scanned >= 3
    assert scan.findings_count > 0


def test_scan_finds_aws_in_env(app, sample_project):
    result = run_scan(
        scan_name="aws",
        source_type="directory",
        source_path=str(sample_project),
    )
    findings = db.session.query(Finding).filter_by(scan_id=result.scan_id).all()
    types = {f.secret_type for f in findings}
    assert "AWS Access Key" in types


def test_finding_never_stores_plaintext(app, sample_project):
    result = run_scan(
        scan_name="no-leak",
        source_type="directory",
        source_path=str(sample_project),
    )
    findings = db.session.query(Finding).filter_by(scan_id=result.scan_id).all()
    for f in findings:
        assert "AKIA" + "A" * 16 not in (f.redacted_value or "")
        assert "a" * 40 not in (f.context_snippet or "")


def test_fingerprint_is_set(app, sample_project):
    result = run_scan(
        scan_name="fp",
        source_type="directory",
        source_path=str(sample_project),
    )
    findings = db.session.query(Finding).filter_by(scan_id=result.scan_id).all()
    for f in findings:
        assert f.fingerprint
        assert len(f.fingerprint) == 64


def test_remediation_attached(app, sample_project):
    result = run_scan(
        scan_name="remed",
        source_type="directory",
        source_path=str(sample_project),
    )
    findings = db.session.query(Finding).filter_by(scan_id=result.scan_id).all()
    aws = next(f for f in findings if f.secret_type == "AWS Access Key")
    assert "Immediate actions" in aws.remediation
    assert "Recommended controls" in aws.remediation


def test_scan_counts_match_findings(app, sample_project):
    result = run_scan(
        scan_name="counts",
        source_type="directory",
        source_path=str(sample_project),
    )
    scan = db.session.get(Scan, result.scan_id)
    findings = db.session.query(Finding).filter_by(scan_id=result.scan_id).all()
    assert scan.findings_count == len(findings)
    assert scan.critical_count == sum(1 for f in findings if f.severity == "critical")
    assert scan.high_count == sum(1 for f in findings if f.severity == "high")


def test_alerts_created_for_critical(app, sample_project):
    result = run_scan(
        scan_name="alerts",
        source_type="directory",
        source_path=str(sample_project),
    )
    alerts = db.session.query(Alert).join(Finding).filter(Finding.scan_id == result.scan_id).all()
    # AWS Access Key in .env should be critical → alert
    assert any(a.alert_type == "critical_secret" for a in alerts)


def test_scan_of_zip_upload(app, sample_project, tmp_path):
    zip_path = tmp_path / "proj.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for file in sample_project.rglob("*"):
            if file.is_file():
                zf.write(file, file.relative_to(sample_project))

    result = run_scan(
        scan_name="zip",
        source_type="zip_upload",
        source_path=None,
        zip_path=str(zip_path),
    )
    assert result.status == "completed"
    assert result.findings_count > 0


def test_scan_of_zip_slip_blocked(app, tmp_path):
    bad = tmp_path / "bad.zip"
    with zipfile.ZipFile(bad, "w") as zf:
        zf.writestr("../evil.txt", "AWS_ACCESS_KEY_ID=AKIA" + "A" * 16)
    result = run_scan(
        scan_name="badzip",
        source_type="zip_upload",
        source_path=None,
        zip_path=str(bad),
    )
    assert result.status == "failed"
    assert result.error_message is not None


def test_scan_of_missing_directory_fails(app):
    result = run_scan(
        scan_name="missing",
        source_type="directory",
        source_path="/does/not/exist/anywhere",
    )
    assert result.status == "failed"


def test_summary_in_result(app, sample_project):
    result = run_scan(
        scan_name="summary",
        source_type="directory",
        source_path=str(sample_project),
    )
    assert result.summary
    assert "by_severity" in result.summary
    assert "by_type" in result.summary
    assert result.summary["total"] == result.findings_count


def test_placeholder_not_critical(app, sample_project):
    result = run_scan(
        scan_name="placeholders",
        source_type="directory",
        source_path=str(sample_project),
    )
    findings = db.session.query(Finding).filter_by(scan_id=result.scan_id).all()
    placeholders = [f for f in findings if "YOUR_API_KEY" in (f.redacted_value or "")]
    for f in placeholders:
        assert f.severity != "critical"