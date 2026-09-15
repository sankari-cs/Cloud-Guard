"""Dashboard route. Shows real stats from Scan and Finding."""
from __future__ import annotations

from flask import Blueprint, render_template
from flask_login import login_required
from sqlalchemy import func, select

from app.extensions import db
from app.models.finding import Finding
from app.models.scan import Scan

dashboard_bp = Blueprint("dashboard", __name__)


def _compute_stats() -> dict:
    total_scans = db.session.scalar(select(func.count(Scan.id))) or 0
    total_findings = db.session.scalar(select(func.count(Finding.id))) or 0

    severity_rows = db.session.execute(
        select(Finding.severity, func.count(Finding.id)).group_by(Finding.severity)
    ).all()
    by_severity = {sev or "informational": count for sev, count in severity_rows}
    for sev in ("critical", "high", "medium", "low", "informational"):
        by_severity.setdefault(sev, 0)

    type_rows = db.session.execute(
        select(Finding.secret_type, func.count(Finding.id))
        .group_by(Finding.secret_type)
        .order_by(func.count(Finding.id).desc())
        .limit(8)
    ).all()
    by_type = [{"name": name, "count": count} for name, count in type_rows]

    avg_risk = db.session.scalar(select(func.avg(Finding.risk_score))) or 0.0
    max_risk = db.session.scalar(select(func.max(Finding.risk_score))) or 0.0

    return {
        "total_scans": total_scans,
        "total_findings": total_findings,
        "by_severity": by_severity,
        "by_type": by_type,
        "average_risk": round(float(avg_risk), 2),
        "max_risk": round(float(max_risk), 2),
    }


@dashboard_bp.route("/")
@login_required
def index():
    stats = _compute_stats()

    recent = (
        db.session.execute(
            select(Finding)
            .order_by(Finding.created_at.desc(), Finding.id.desc())
            .limit(10)
        )
        .scalars()
        .all()
    )

    # For bar widths, use the maximum count so the bars scale.
    severity_max = max(stats["by_severity"].values()) if stats["by_severity"] else 1
    type_max = max((t["count"] for t in stats["by_type"]), default=1) or 1

    return render_template(
        "dashboard.html",
        stats=stats,
        recent=recent,
        severity_max=severity_max or 1,
        type_max=type_max,
        severity_order=["critical", "high", "medium", "low", "informational"],
    )