"""Tests for the authentication layer."""
import pytest
from app import create_app
from app.config import TestingConfig
from app.extensions import db
from app.models.audit_log import AuditLog
from app.models.user import User
@pytest.fixture()
def app():
    app = create_app(TestingConfig)
    with app.app_context():
        db.create_all()
        admin = User(username="admin", role="admin")
        admin.set_password("AdminPass123!")
        db.session.add(admin)
        viewer = User(username="viewer", role="viewer")
        viewer.set_password("ViewerPass123!")
        db.session.add(viewer)
        db.session.commit()
        yield app
        db.session.remove()
        db.drop_all()
@pytest.fixture()
def client(app):
    return app.test_client()
def test_login_page_get(client):
    r = client.get("/login")
    assert r.status_code == 200
    assert b"CloudGuard" in r.data
    assert b"Sign in" in r.data
def test_dashboard_requires_login(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code in (302, 401)
    if r.status_code == 302:
        assert "/login" in r.headers["Location"]
def test_login_with_wrong_password(client):
    r = client.post("/login", data={"username": "admin", "password": "nope"})
    assert r.status_code == 401
    assert b"Invalid username or password" in r.data
def test_login_with_unknown_user(client):
    r = client.post("/login", data={"username": "ghost", "password": "whatever"})
    assert r.status_code == 401
def test_login_success(client):
    r = client.post(
        "/login",
        data={"username": "admin", "password": "AdminPass123!"},
        follow_redirects=True,
    )
    assert r.status_code == 200
    assert b"Dashboard" in r.data or b"Welcome" in r.data
def test_login_success_writes_audit(app, client):
    client.post("/login", data={"username": "admin", "password": "AdminPass123!"})
    with app.app_context():
        log = AuditLog.query.filter_by(action="login_success").first()
        assert log is not None
        assert log.user_id is not None
def test_login_failure_writes_audit(app, client):
    client.post("/login", data={"username": "admin", "password": "wrong"})
    with app.app_context():
        log = AuditLog.query.filter_by(action="login_failed").first()
        assert log is not None
def test_logout(client):
    client.post("/login", data={"username": "admin", "password": "AdminPass123!"})
    r = client.post("/logout", follow_redirects=True)
    assert r.status_code == 200
    r2 = client.get("/", follow_redirects=False)
    assert r2.status_code in (302, 401)
def test_inactive_user_cannot_login(app, client):
    with app.app_context():
        u = User(username="disabled", role="viewer", is_active=False)
        u.set_password("DisabledPass123!")
        db.session.add(u)
        db.session.commit()
    r = client.post("/login", data={"username": "disabled", "password": "DisabledPass123!"})
    assert r.status_code == 401
def test_password_strength_policy():
    from app.security import validate_password_strength
    ok, _ = validate_password_strength("short")
    assert ok is False
    ok, _ = validate_password_strength("alllowercaseonly")
    assert ok is False
    ok, _ = validate_password_strength("StrongPass123!")
    assert ok is True
def test_require_role_decorator_allows_admin(app, client):
    from app.security import require_role
    from flask import Blueprint, jsonify
    probe_bp = Blueprint("probe", __name__)
    @probe_bp.route("/probe/admin")
    @require_role("admin")
    def probe_admin():
        return jsonify(ok=True)
    @probe_bp.route("/probe/analyst")
    @require_role("analyst")
    def probe_analyst():
        return jsonify(ok=True)
    app.register_blueprint(probe_bp)
    client.post("/login", data={"username": "admin", "password": "AdminPass123!"})
    r = client.get("/probe/admin")
    assert r.status_code == 200
    r = client.get("/probe/analyst")
    assert r.status_code == 403
def test_require_role_decorator_blocks_anonymous(app):
    from app.security import require_role
    from flask import Blueprint, jsonify
    probe_bp = Blueprint("probe_anon", __name__)
    @probe_bp.route("/probe_anon")
    @require_role("admin")
    def probe_admin():
        return jsonify(ok=True)
    app.register_blueprint(probe_bp)
    client = app.test_client()
    r = client.get("/probe_anon")
    assert r.status_code in (302, 401)
