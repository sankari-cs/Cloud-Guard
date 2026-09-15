"""Tests for the settings page."""
import pytest

from app import create_app
from app.config import TestingConfig
from app.extensions import db
from app.models.setting import Setting
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


def test_settings_requires_login(client):
    r = client.get("/settings/", follow_redirects=False)
    assert r.status_code in (302, 401)


def test_settings_renders_defaults(client):
    _login(client)
    r = client.get("/settings/")
    assert r.status_code == 200
    body = r.data.decode("utf-8")
    assert "Max upload size" in body
    assert "Entropy threshold" in body


def test_settings_saves_values(app, client):
    _login(client)
    r = client.post(
        "/settings/",
        data={
            "max_upload_mb": "100",
            "max_files_per_scan": "1000",
            "max_findings_per_scan": "500",
            "entropy_threshold": "4.0",
            "severity_critical": "90",
            "severity_high": "75",
            "severity_medium": "55",
            "severity_low": "30",
            "excluded_dirs": ".git,node_modules",
        },
        follow_redirects=True,
    )
    assert r.status_code == 200
    with app.app_context():
        row = db.session.query(Setting).filter_by(key="max_upload_mb").first()
        assert row is not None
        assert row.value == "100"


def test_settings_reload_shows_saved_values(app, client):
    _login(client)
    client.post(
        "/settings/",
        data={
            "max_upload_mb": "77",
            "max_files_per_scan": "1000",
            "max_findings_per_scan": "500",
            "entropy_threshold": "3.8",
            "severity_critical": "88",
            "severity_high": "72",
            "severity_medium": "52",
            "severity_low": "26",
            "excluded_dirs": ".git",
        },
    )
    r = client.get("/settings/")
    body = r.data.decode("utf-8")
    assert "77" in body