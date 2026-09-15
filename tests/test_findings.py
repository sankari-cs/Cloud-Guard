"""Tests for findings list, detail, and triage."""
import pytest

from app import create_app
from app.config import TestingConfig
from app.extensions import db
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.user import User


@pytest.fixture()
def app():
    app = create_app(TestingConfig)
    with app.app_context():
        db.create_all()

        admin = User(username="admin", role="admin")
        admin.set_password("AdminPass123!")
        db.session.add(admin)

        scan = Scan(scan_name="demo", source_type="directory", status="completed")
        db.session.add(scan)
        db.session.commit()

        for sev, score, stype, path in [
            ("critical", 95.0, "AWS Access Key", ".env"),
            ("high", 78.0, "GitHub Token", "src/ci.py"),
            ("medium", 60.0, "Password", "app/settings.py"),
            ("low", 30.0, "JWT", "api/client.ts"),
        ]:
            db.session.add(Finding(
                scan_id=scan.id,
                secret_type=stype,
                file_path=path,
                line_number=1,
                redacted_value="AKIA****",
                fingerprint="fp" + stype,
                confidence=0.9,
                validation_status="format_valid",
                risk_score=score,
                severity=sev,
                remediation="Immediate actions",
                detection_reason="matched rule test",
                context_snippet="line with redacted value",
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


def test_findings_requires_login(client):
    r = client.get("/findings/", follow_redirects=False)
    assert r.status_code in (302, 401)


def test_findings_lists_all(client):
    _login(client)
    r = client.get("/findings/")
    assert r.status_code == 200
    body = r.data.decode("utf-8")
    assert "AWS Access Key" in body
    assert "GitHub Token" in body
    assert "Password" in body
    assert "JWT" in body
def _table_rows(body: str) -> str:
    """Return only the findings table body, ignoring dropdowns and chrome."""
    start = body.find("<tbody>")
    end = body.find("</tbody>")
    if start == -1 or end == -1:
        return ""
    return body[start:end]


def test_findings_filter_by_severity(client):
    _login(client)
    r = client.get("/findings/?severity=critical")
    body = r.data.decode("utf-8")
    rows = _table_rows(body)
    assert "AWS Access Key" in rows
    assert "GitHub Token" not in rows


def test_findings_filter_by_type(client):
    _login(client)
    r = client.get("/findings/?type=Password")
    body = r.data.decode("utf-8")
    rows = _table_rows(body)
    assert "Password" in rows
    assert "AWS Access Key" not in rows

def test_findings_search(client):
    _login(client)
    r = client.get("/findings/?q=.env")
    body = r.data.decode("utf-8")
    assert ".env" in body


def test_finding_detail(app, client):
    _login(client)
    with app.app_context():
        f = Finding.query.filter_by(secret_type="AWS Access Key").first()
        fid = f.id
    r = client.get(f"/findings/{fid}")
    assert r.status_code == 200
    body = r.data.decode("utf-8")
    assert "AWS Access Key" in body
    assert "Redacted value" in body
    assert "Remediation" in body
    assert "Context" in body


def test_finding_detail_404(client):
    _login(client)
    r = client.get("/findings/99999")
    assert r.status_code == 404


def test_finding_triage(app, client):
    _login(client)
    with app.app_context():
        f = Finding.query.filter_by(secret_type="JWT").first()
        fid = f.id

    r = client.post(
        f"/findings/{fid}/triage",
        data={"status": "resolved"},
        follow_redirects=True,
    )
    assert r.status_code == 200

    with app.app_context():
        f = db.session.get(Finding, fid)
        assert f.triage_status == "resolved"


def test_finding_triage_invalid_status(app, client):
    _login(client)
    with app.app_context():
        f = Finding.query.filter_by(secret_type="JWT").first()
        fid = f.id
        old_status = f.triage_status

    r = client.post(
        f"/findings/{fid}/triage",
        data={"status": "not-a-status"},
        follow_redirects=True,
    )
    assert r.status_code == 200

    with app.app_context():
        f = db.session.get(Finding, fid)
        assert f.triage_status == old_status