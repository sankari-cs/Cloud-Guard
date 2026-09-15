"""Tests for alerts list and acknowledge."""
import pytest

from app import create_app
from app.config import TestingConfig
from app.extensions import db
from app.models.alert import Alert
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

        f = Finding(
            scan_id=scan.id, secret_type="AWS Access Key", file_path=".env",
            line_number=1, redacted_value="AKIA****", fingerprint="fp1",
            confidence=0.9, validation_status="format_valid",
            risk_score=95.0, severity="critical", remediation="x",
            detection_reason="x", context_snippet="x", triage_status="open",
        )
        db.session.add(f)
        db.session.commit()

        db.session.add(Alert(
            finding_id=f.id, alert_type="critical_secret",
            severity="critical", status="open",
        ))
        db.session.add(Alert(
            finding_id=f.id, alert_type="private_key_detected",
            severity="critical", status="acknowledged",
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


def test_alerts_requires_login(client):
    r = client.get("/alerts/", follow_redirects=False)
    assert r.status_code in (302, 401)


def test_alerts_lists_open(client):
    _login(client)
    r = client.get("/alerts/?show=open")
    assert r.status_code == 200
    body = r.data.decode("utf-8")
    assert "critical_secret" in body


def test_alerts_hides_acknowledged_by_default(client):
    _login(client)
    r = client.get("/alerts/?show=open")
    body = r.data.decode("utf-8")
    assert "private_key_detected" not in body


def test_alerts_shows_acknowledged_tab(client):
    _login(client)
    r = client.get("/alerts/?show=acknowledged")
    body = r.data.decode("utf-8")
    assert "private_key_detected" in body
    assert "critical_secret" not in body


def test_alerts_all_tab(client):
    _login(client)
    r = client.get("/alerts/?show=all")
    body = r.data.decode("utf-8")
    assert "critical_secret" in body
    assert "private_key_detected" in body


def test_alerts_links_to_finding(app, client):
    _login(client)
    with app.app_context():
        f = Finding.query.first()
        fid = f.id
    r = client.get("/alerts/?show=all")
    body = r.data.decode("utf-8")
    assert f"/findings/{fid}" in body


def test_acknowledge_alert(app, client):
    _login(client)
    with app.app_context():
        a = Alert.query.filter_by(status="open").first()
        aid = a.id
    r = client.post(f"/alerts/{aid}/acknowledge", follow_redirects=True)
    assert r.status_code == 200
    with app.app_context():
        a = db.session.get(Alert, aid)
        assert a.status == "acknowledged"
        assert a.acknowledged_at is not None


def test_acknowledge_missing_404(client):
    _login(client)
    r = client.post("/alerts/99999/acknowledge")
    assert r.status_code == 404