"""Tests for the New Scan page."""
import io
import zipfile
import pytest
from app import create_app
from app.config import TestingConfig
from app.extensions import db
from app.models.scan import Scan
from app.models.user import User
@pytest.fixture()
def app(tmp_path):
    class T(TestingConfig):
        UPLOAD_FOLDER = str(tmp_path / "uploads")
        REPORTS_FOLDER = str(tmp_path / "reports")
    app = create_app(T)
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
def test_new_scan_requires_login(client):
    r = client.get("/scans/new", follow_redirects=False)
    assert r.status_code in (302, 401)
def test_new_scan_page_renders(client):
    _login(client)
    r = client.get("/scans/new")
    assert r.status_code == 200
    body = r.data.decode("utf-8")
    assert "New Scan" in body
    assert "Directory" in body
    assert "Upload ZIP" in body
def test_scan_directory_success(app, client, tmp_path):
    _login(client)
    project = tmp_path / "project"
    project.mkdir()
    (project / ".env").write_text(
        'AWS_ACCESS_KEY_ID="AKIA' + "A" * 16 + '"\n'
        'password = "S3cr3tP@ssw0rd!12345"\n',
        encoding="utf-8",
    )
    r = client.post(
        "/scans/new",
        data={
            "mode": "directory",
            "scan_name": "local-scan",
            "directory": str(project),
        },
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert "/scans/" in r.headers["Location"]
    with app.app_context():
        s = Scan.query.filter_by(scan_name="local-scan").first()
        assert s is not None
        assert s.status == "completed"
        assert s.findings_count >= 1
def test_scan_directory_missing_path(app, client):
    _login(client)
    r = client.post(
        "/scans/new",
        data={
            "mode": "directory",
            "scan_name": "bad",
            "directory": "C:/does/not/exist/anywhere",
        },
        follow_redirects=True,
    )
    assert r.status_code == 200
    body = r.data.decode("utf-8")
    assert "failed" in body.lower() or "Directory not found" in body
def test_scan_directory_empty_path(app, client):
    _login(client)
    r = client.post(
        "/scans/new",
        data={"mode": "directory", "scan_name": "empty", "directory": ""},
        follow_redirects=True,
    )
    assert r.status_code == 200
    assert b"Please enter a directory path" in r.data
def test_scan_zip_success(app, client):
    _login(client)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(".env", 'AWS_ACCESS_KEY_ID="AKIA' + "A" * 16 + '"\n')
        zf.writestr("src/app.py", "x = 1\n")
    buf.seek(0)
    r = client.post(
        "/scans/new",
        data={
            "mode": "zip",
            "scan_name": "zip-scan",
            "zip_file": (buf, "project.zip"),
        },
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    assert r.status_code == 302
    with app.app_context():
        s = Scan.query.filter_by(scan_name="zip-scan").first()
        assert s is not None
        assert s.status == "completed"
def test_scan_zip_rejects_non_zip(app, client):
    _login(client)
    buf = io.BytesIO(b"not a zip")
    r = client.post(
        "/scans/new",
        data={
            "mode": "zip",
            "scan_name": "bad",
            "zip_file": (buf, "not.txt"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert b"Only .zip files are allowed" in r.data
def test_scan_zip_slip_blocked(app, client):
    _login(client)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../evil.txt", "AKIA" + "A" * 16)
    buf.seek(0)
    r = client.post(
        "/scans/new",
        data={
            "mode": "zip",
            "scan_name": "slip",
            "zip_file": (buf, "evil.zip"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert r.status_code == 200
    assert b"failed" in r.data.lower() or b"Directory" in r.data
