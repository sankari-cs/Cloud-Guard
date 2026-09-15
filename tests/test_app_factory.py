"""Smoke tests for the Flask application factory."""
from app import create_app
from app.config import TestingConfig
from app.extensions import db


def test_create_app():
    app = create_app(TestingConfig)
    assert app is not None
    assert app.config["TESTING"] is True


def test_health_endpoint():
    app = create_app(TestingConfig)
    client = app.test_client()
    response = client.get("/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "ok"
    assert data["service"] == "cloudguard"


def test_models_create_all():
    app = create_app(TestingConfig)
    with app.app_context():
        db.create_all()
        from app.models import User, Scan, Finding, Alert, Setting, AuditLog  # noqa: F401

        user = User(username="tester", role="admin")
        user.set_password("does-not-matter")
        db.session.add(user)
        db.session.commit()

        assert user.id is not None
        assert user.check_password("does-not-matter") is True
        assert user.check_password("wrong") is False

        scan = Scan(scan_name="first scan", source_type="directory", created_by=user.id)
        db.session.add(scan)
        db.session.commit()
        assert scan.id is not None
        assert scan.status == "pending"

        db.drop_all()