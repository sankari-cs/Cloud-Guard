"""Tests for report generation and download."""
import pytest

from app import create_app
from app.config import TestingConfig
from app.extensions import db
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.user import User


@pytest.fixture()
def app(tmp_path):
    class T(TestingConfig):
        REPORTS_FOLDER = str(tmp_path / "reports")
        UPLOAD_FOLDER = str(tmp_path / "uploads")

    app = create_app(T)
    with app.app_context():
        db.create_all()

        admin = User(username="admin", role="admin")
        admin.set_password("AdminPass123!")
        db.session.add(admin)

        scan = Scan(
            scan_name="prod-monorepo",
            source_type="directory",
            status="completed",
            files_scanned=10,
            findings_count=1,
            risk_score=90.0,
        )
        db.session.add(scan)
        db.session.commit()

        db.session.add(Finding(
            scan_id=scan.id,
            secret_type="AWS Access Key",
            file_path=".env",
            line_number=1,
            redacted_value="AKIA****",
            fingerprint="fp1",
            confidence=0.9,
            validation_status="format_valid",
            risk_score=90.0,
            severity="critical",
            remediation="x",
            detection_reason="x",
            context_snippet="x",
            triage_status="open",
        ))
        db.session.commit()

        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


def _login(client):
    return client.post(
        "/login",
        data={"username": "admin", "password": "AdminPass123!"},
        follow_redirects=True,
    )


def test_reports_requires_login(client):
    r = client.get("/reports/", follow_redirects=False)
    assert r.status_code in (302, 401)


def test_reports_page_renders(app, client):
    _login(client)
    r = client.get("/reports/")
    assert r.status_code == 200
    body = r.data.decode("utf-8")
    assert "Generate report" in body
    assert "prod-monorepo" in body


def test_generate_json_report(app, client):
    _login(client)
    with app.app_context():
        s = Scan.query.filter_by(scan_name="prod-monorepo").first()
        sid = s.id

    r = client.post(
        "/reports/generate",
        data={"scan_id": sid, "format": "json"},
        follow_redirects=False,
    )
    # 302 to download
    assert r.status_code in (200, 302)
    if r.status_code == 302:
        loc = r.headers["Location"]
        assert "/reports/download/" in loc

    with app.app_context():
        import os
        from pathlib import Path
        rdir = Path(app.config["REPORTS_FOLDER"])
        files = list(rdir.glob("cloudguard_*prod-monorepo*json"))
        assert files, "JSON report was not written"


def test_generate_csv_report(app, client):
    _login(client)
    with app.app_context():
        s = Scan.query.filter_by(scan_name="prod-monorepo").first()
        sid = s.id
    client.post("/reports/generate", data={"scan_id": sid, "format": "csv"})
    with app.app_context():
        from pathlib import Path
        rdir = Path(app.config["REPORTS_FOLDER"])
        files = list(rdir.glob("*.csv"))
        assert files


def test_generate_html_report(app, client):
    _login(client)
    with app.app_context():
        s = Scan.query.filter_by(scan_name="prod-monorepo").first()
        sid = s.id
    client.post("/reports/generate", data={"scan_id": sid, "format": "html"})
    with app.app_context():
        from pathlib import Path
        rdir = Path(app.config["REPORTS_FOLDER"])
        files = list(rdir.glob("*.html"))
        assert files
        content = files[0].read_text(encoding="utf-8")
        assert "CloudGuard Security Report" in content
        assert "AKIA" + "A" * 16 not in content


def test_generate_pdf_report(app, client):
    _login(client)
    with app.app_context():
        s = Scan.query.filter_by(scan_name="prod-monorepo").first()
        sid = s.id
    client.post("/reports/generate", data={"scan_id": sid, "format": "pdf"})
    with app.app_context():
        from pathlib import Path
        rdir = Path(app.config["REPORTS_FOLDER"])
        files = list(rdir.glob("*.pdf"))
        assert files
        assert files[0].read_bytes().startswith(b"%PDF")


def test_generate_invalid_format(app, client):
    _login(client)
    with app.app_context():
        s = Scan.query.filter_by(scan_name="prod-monorepo").first()
        sid = s.id
    r = client.post(
        "/reports/generate",
        data={"scan_id": sid, "format": "exe"},
        follow_redirects=True,
    )
    assert b"Unsupported format" in r.data


def test_generate_missing_scan(app, client):
    _login(client)
    r = client.post(
        "/reports/generate",
        data={"scan_id": 99999, "format": "pdf"},
        follow_redirects=True,
    )
    assert b"Scan not found" in r.data


def test_download_rejects_traversal(app, client):
    _login(client)
    r = client.get("/reports/download/..%2F..%2F..%2Fetc%2Fpasswd")
    assert r.status_code == 404