"""Alert list and acknowledge routes."""
from __future__ import annotations

from datetime import datetime, timezone

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from sqlalchemy import select

from app.extensions import db
from app.models.alert import Alert
from app.models.finding import Finding

alerts_bp = Blueprint("alerts", __name__, url_prefix="/alerts")

SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]


@alerts_bp.route("/")
@login_required
def index():
    show = (request.args.get("show") or "open").strip().lower()

    stmt = select(Alert).order_by(Alert.created_at.desc(), Alert.id.desc())
    if show == "open":
        stmt = stmt.where(Alert.status != "acknowledged")
    elif show == "acknowledged":
        stmt = stmt.where(Alert.status == "acknowledged")

    alerts = db.session.execute(stmt).scalars().all()

    # Attach findings for display without N+1
    finding_ids = [a.finding_id for a in alerts if a.finding_id]
    findings = {}
    if finding_ids:
        rows = db.session.execute(
            select(Finding).where(Finding.id.in_(finding_ids))
        ).scalars().all()
        findings = {f.id: f for f in rows}

    return render_template(
        "alerts.html",
        alerts=alerts,
        findings=findings,
        show=show,
        severity_order=SEVERITY_ORDER,
    )


@alerts_bp.route("/<int:alert_id>/acknowledge", methods=["POST"])
@login_required
def acknowledge(alert_id: int):
    alert = db.session.get(Alert, alert_id)
    if alert is None:
        abort(404)

    alert.status = "acknowledged"
    alert.acknowledged_at = datetime.now(timezone.utc)
    alert.acknowledged_by = current_user.id
    db.session.commit()

    flash("Alert acknowledged.", "success")
    return redirect(url_for("alerts.index"))