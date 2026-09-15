from datetime import datetime, timezone
from app.extensions import db


class Scan(db.Model):
    __tablename__ = "scans"
    id = db.Column(db.Integer, primary_key=True)
    scan_name = db.Column(db.String(255), nullable=False)
    source_type = db.Column(db.String(50), nullable=False)
    source_path = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), nullable=False, default="pending")
    started_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    completed_at = db.Column(db.DateTime(timezone=True), nullable=True)
    files_scanned = db.Column(db.Integer, default=0)
    findings_count = db.Column(db.Integer, default=0)
    critical_count = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    low_count = db.Column(db.Integer, default=0)
    info_count = db.Column(db.Integer, default=0)
    risk_score = db.Column(db.Float, default=0.0)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    error_message = db.Column(db.Text, nullable=True)

    findings = db.relationship("Finding", backref="scan", cascade="all, delete-orphan", lazy="dynamic")