from app import create_app
from app.config import TestingConfig
from app.extensions import db
from app.models.user import User
from app.models.scan import Scan
from app.models.finding import Finding
app = create_app(TestingConfig)
with app.app_context():
    db.create_all()
    u = User(username="admin", role="admin"); u.set_password("AdminPass123!")
    db.session.add(u)
    s = Scan(scan_name="demo", source_type="directory", status="completed")
    db.session.add(s); db.session.commit()
    db.session.add(Finding(
        scan_id=s.id, secret_type="AWS Access Key", file_path=".env", line_number=1,
        redacted_value="AKIA****", fingerprint="fp1", confidence=0.9,
        validation_status="format_valid", risk_score=95.0, severity="critical",
        remediation="x", detection_reason="x", context_snippet="x", triage_status="open",
    ))
    db.session.add(Finding(
        scan_id=s.id, secret_type="GitHub Token", file_path="src/ci.py", line_number=1,
        redacted_value="ghp_****", fingerprint="fp2", confidence=0.9,
        validation_status="format_valid", risk_score=78.0, severity="high",
        remediation="x", detection_reason="x", context_snippet="x", triage_status="open",
    ))
    db.session.commit()
    c = app.test_client()
    c.post("/login", data={"username": "admin", "password": "AdminPass123!"})
    body = c.get("/findings/?severity=critical").data.decode("utf-8")
    print("=== first 200 chars ===")
    print(body[:200])
    print("=== last 200 chars ===")
    print(body[-200:])
