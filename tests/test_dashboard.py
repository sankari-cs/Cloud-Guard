"""Tests for the dashboard route and stats."""
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


def test_dashboard_redirects_when_anonymous(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code in (302, 401)


def test_dashboard_renders_empty(client):
    _login(client)
    r = client.get("/")
    assert r.status_code == 200
    assert b"Dashboard" in r.data
    assert b"Total Scans" in r.data
    assert b"Total Findings" in r.data


def test_dashboard_shows_real_counts(app, client):
    with app.app_context():
        scan = Scan(scan_name="demo", source_type="directory", status="completed")
        db.session.add(scan)
        db.session.commit()

        for sev, score in [
            ("critical", 95.0),
            ("high", 78.0),
            ("medium", 60.0),
            ("low", 30.0),
        ]:
            db.session.add(Finding(
                scan_id=scan.id,
                secret_type="AWS Access Key",
                file_path=".env",
                line_number=1,
                redacted_value="AKIA****",
                fingerprint="fp",
                confidence=0.9,
                validation_status="format_valid",
                risk_score=score,
                severity=sev,
            ))
        db.session.commit()

    _login(client)
    r = client.get("/")
    body = r.data.decode("utf-8")
    assert r.status_code == 200
    # Scan count
    assert ">1<" in body
    # Findings count
    assert ">4<" in body
    # Severities rendered
    assert "critical" in body
    assert "high" in body


def test_dashboard_recent_findings_listed(app, client):
    with app.app_context():
        scan = Scan(scan_name="recent", source_type="directory", status="completed")
        db.session.add(scan)
        db.session.commit()

        db.session.add(Finding(
            scan_id=scan.id,
            secret_type="GitHub Token",
            file_path="src/ci.py",
            line_number=42,
            redacted_value="ghp_****",
            fingerprint="fp2",
            confidence=0.95,
            validation_status="format_valid",
            risk_score=81.0,
            severity="high",
        ))
        db.session.commit()

    _login(client)
    r = client.get("/")
    body = r.data.decode("utf-8")
    assert "src/ci.py" in body
    assert "GitHub Token" in body


def test_dashboard_average_risk_uses_real_data(app, client):
    with app.app_context():
        scan = Scan(scan_name="avg", source_type="directory", status="completed")
        db.session.add(scan)
        db.session.commit()

        db.session.add(Finding(
            scan_id=scan.id,
            secret_type="Password",
            file_path="app.py",
            line_number=1,
            redacted_value="REDACTED",
            fingerprint="fp3",
            confidence=0.5,
            validation_status="format_valid",
            risk_score=40.0,
            severity="low",
        ))
        db.session.add(Finding(
            scan_id=scan.id,
            secret_type="Password",
            file_path="app2.py",
            line_number=1,
            redacted_value="REDACTED",
            fingerprint="fp4",
            confidence=0.5,
            validation_status="format_valid",
            risk_score=60.0,
            severity="medium",
        ))
        db.session.commit()

    _login(client)
    r = client.get("/")
    body = r.data.decode("utf-8")
    # Average of 40 and 60 = 50.0
    assert "50.0" in body


def test_dashboard_requires_login(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code in (302, 401)