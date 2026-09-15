"""Report generation and download routes."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import login_required
from sqlalchemy import select

from app.extensions import db
from app.models.finding import Finding
from app.models.scan import Scan
from app.services.reporting import (
    build_report_data,
    render_csv,
    render_html,
    render_pdf,
)

reports_bp = Blueprint("reports", __name__, url_prefix="/reports")

ALLOWED_FORMATS = {"json", "csv", "html", "pdf"}


def _reports_dir() -> Path:
    path = Path(current_app.config["REPORTS_FOLDER"])
    path.mkdir(parents=True, exist_ok=True)
    return path


def _list_reports() -> list[dict]:
    """Return metadata for every file in the reports folder."""
    out: list[dict] = []
    for p in sorted(_reports_dir().glob("cloudguard_*"), reverse=True):
        if not p.is_file():
            continue
        stat = p.stat()
        out.append({
            "name": p.name,
            "size": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
            "format": p.suffix.lstrip(".").upper(),
        })
    return out


@reports_bp.route("/")
@login_required
def index():
    scans = db.session.execute(
        select(Scan).order_by(Scan.id.desc())
    ).scalars().all()
    reports = _list_reports()
    return render_template("reports.html", scans=scans, reports=reports)


@reports_bp.route("/generate", methods=["POST"])
@login_required
def generate():
    scan_id = request.form.get("scan_id", type=int)
    fmt = (request.form.get("format") or "pdf").strip().lower()

    if fmt not in ALLOWED_FORMATS:
        flash("Unsupported format.", "error")
        return redirect(url_for("reports.index"))

    scan = db.session.get(Scan, scan_id) if scan_id else None
    if scan is None:
        flash("Scan not found.", "error")
        return redirect(url_for("reports.index"))

    findings = db.session.execute(
        select(Finding).where(Finding.scan_id == scan.id).order_by(Finding.id)
    ).scalars().all()

    data = build_report_data(scan, findings)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_name = "".join(c for c in scan.scan_name if c.isalnum() or c in "-_")[:40] or "scan"
    base = f"cloudguard_{safe_name}_{scan.id}_{ts}"
    out_dir = _reports_dir()

    if fmt == "json":
        path = out_dir / f"{base}.json"
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    elif fmt == "csv":
        path = out_dir / f"{base}.csv"
        path.write_text(render_csv(data), encoding="utf-8")
    elif fmt == "html":
        path = out_dir / f"{base}.html"
        path.write_text(render_html(data), encoding="utf-8")
    else:  # pdf
        path = out_dir / f"{base}.pdf"
        path.write_bytes(render_pdf(data))

    flash(f"Report generated: {path.name}", "success")
    return redirect(url_for("reports.download", filename=path.name))


@reports_bp.route("/download/<path:filename>")
@login_required
def download(filename: str):
    # Only allow files that live directly inside the reports folder,
    # no traversal, no absolute paths.
    target = (_reports_dir() / filename).resolve()
    reports_dir = _reports_dir().resolve()
    if reports_dir not in target.parents and target.parent != reports_dir:
        abort(404)
    if not target.is_file():
        abort(404)
    return send_file(
        str(target),
        as_attachment=True,
        download_name=target.name,
    )