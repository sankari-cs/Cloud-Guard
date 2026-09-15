from datetime import datetime, timezone
from app.extensions import db


class Finding(db.Model):
    __tablename__ = "findings"
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False, index=True)
    secret_type = db.Column(db.String(100), nullable=False, index=True)
    file_path = db.Column(db.Text, nullable=False)
    line_number = db.Column(db.Integer, nullable=True)
    column_number = db.Column(db.Integer, nullable=True)
    redacted_value = db.Column(db.String(255), nullable=False)
    fingerprint = db.Column(db.String(64), nullable=False, index=True)
    confidence = db.Column(db.Float, default=0.0)
    validation_status = db.Column(db.String(30), default="unknown")
    risk_score = db.Column(db.Float, default=0.0)
    severity = db.Column(db.String(20), nullable=False, index=True)
    remediation = db.Column(db.Text, nullable=True)
    detection_reason = db.Column(db.Text, nullable=True)
    context_snippet = db.Column(db.Text, nullable=True)
    triage_status = db.Column(db.String(20), default="open", index=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    alerts = db.relationship("Alert", backref="finding", cascade="all, delete-orphan", lazy="dynamic")