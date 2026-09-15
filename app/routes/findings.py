"""Findings list, detail, and triage routes."""
from __future__ import annotations

from flask import (
    Blueprint,
    abort,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import login_required
from sqlalchemy import or_, select

from app.extensions import db
from app.models.finding import Finding
from app.models.scan import Scan

findings_bp = Blueprint("findings", __name__, url_prefix="/findings")

SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]
VALID_TRIAGE = {"open", "false_positive", "resolved", "ignored"}
PAGE_SIZE = 25


def _severity_rank(label: str) -> int:
    try:
        return SEVERITY_ORDER.index((label or "").lower())
    except ValueError:
        return len(SEVERITY_ORDER)


@findings_bp.route("/")
@login_required
def index():
    severity = (request.args.get("severity") or "").strip().lower()
    secret_type = (request.args.get("type") or "").strip()
    scan_id = request.args.get("scan", type=int)
    q = (request.args.get("q") or "").strip()
    sort = (request.args.get("sort") or "risk").strip()
    order = (request.args.get("order") or "desc").strip()
    page = max(1, request.args.get("page", type=int) or 1)

    stmt = select(Finding)

    if severity in SEVERITY_ORDER:
        stmt = stmt.where(Finding.severity == severity)
    if secret_type:
        stmt = stmt.where(Finding.secret_type == secret_type)
    if scan_id:
        stmt = stmt.where(Finding.scan_id == scan_id)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(Finding.file_path.ilike(like), Finding.secret_type.ilike(like)))

    sort_python = False
    if sort == "severity":
        sort_python = True
        sort_col = Finding.risk_score
    elif sort == "file":
        sort_col = Finding.file_path
    elif sort == "created":
        sort_col = Finding.created_at
    else:
        sort_col = Finding.risk_score

    if not sort_python:
        stmt = stmt.order_by(sort_col.desc() if order == "desc" else sort_col.asc())

    stmt = stmt.order_by(Finding.id.desc())

    rows = db.session.execute(stmt).scalars().all()

    if sort_python:
        rows = sorted(rows, key=lambda f: (_severity_rank(f.severity), -float(f.risk_score or 0)))
        if order == "desc":
            rows = list(reversed(rows))

    total = len(rows)
    start = (page - 1) * PAGE_SIZE
    end = start + PAGE_SIZE
    page_rows = rows[start:end]
    total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)

    types = [
        t for (t,) in db.session.execute(
            select(Finding.secret_type).group_by(Finding.secret_type).order_by(Finding.secret_type)
        ).all()
    ]
    scans = db.session.execute(select(Scan).order_by(Scan.id.desc())).scalars().all()

    return render_template(
        "findings.html",
        findings=page_rows,
        total=total,
        page=page,
        total_pages=total_pages,
        severity_order=SEVERITY_ORDER,
        types=types,
        scans=scans,
        filters={
            "severity": severity,
            "type": secret_type,
            "scan": scan_id,
            "q": q,
            "sort": sort,
            "order": order,
        },
    )


@findings_bp.route("/<int:finding_id>")
@login_required
def detail(finding_id: int):
    finding = db.session.get(Finding, finding_id)
    if finding is None:
        abort(404)
    scan = db.session.get(Scan, finding.scan_id)
    return render_template("finding_detail.html", finding=finding, scan=scan)


@findings_bp.route("/<int:finding_id>/triage", methods=["POST"])
@login_required
def triage(finding_id: int):
    finding = db.session.get(Finding, finding_id)
    if finding is None:
        abort(404)

    new_status = (request.form.get("status") or "").strip()
    if new_status not in VALID_TRIAGE:
        flash("Invalid triage status.", "error")
        return redirect(url_for("findings.detail", finding_id=finding_id))

    finding.triage_status = new_status
    db.session.commit()
    flash(f"Triage status set to '{new_status}'.", "success")
    return redirect(url_for("findings.detail", finding_id=finding_id))