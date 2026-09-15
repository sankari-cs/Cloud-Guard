"""Scan history, scan detail, and new scan routes."""
from __future__ import annotations
import secrets
from pathlib import Path
from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required
from sqlalchemy import select
from werkzeug.utils import secure_filename
from app.extensions import db
from app.models.finding import Finding
from app.models.scan import Scan
from app.services.orchestrator import run_scan
scans_bp = Blueprint("scans", __name__, url_prefix="/scans")
SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]
ALLOWED_UPLOAD_EXTENSIONS = {".zip"}
MAX_UPLOAD_BYTES = 50 * 1024 * 1024
@scans_bp.route("/")
@login_required
def index():
    scans = db.session.execute(
        select(Scan).order_by(Scan.id.desc())
    ).scalars().all()
    return render_template("scans.html", scans=scans)
@scans_bp.route("/new", methods=["GET", "POST"])
@login_required
def new():
    if request.method == "GET":
        return render_template("new_scan.html")
    mode = (request.form.get("mode") or "directory").strip()
    scan_name = (request.form.get("scan_name") or "").strip() or "unnamed"
    if mode == "zip":
        file = request.files.get("zip_file")
        if file is None or not file.filename:
            flash("Please choose a ZIP file.", "error")
            return redirect(url_for("scans.new"))
        filename = secure_filename(file.filename) or "upload.zip"
        ext = Path(filename).suffix.lower()
        if ext not in ALLOWED_UPLOAD_EXTENSIONS:
            flash("Only .zip files are allowed.", "error")
            return redirect(url_for("scans.new"))
        file.seek(0, 2)
        size = file.tell()
        file.seek(0)
        if size > MAX_UPLOAD_BYTES:
            flash("ZIP file is larger than 50 MB.", "error")
            return redirect(url_for("scans.new"))
        upload_dir = Path(current_app.config["UPLOAD_FOLDER"])
        upload_dir.mkdir(parents=True, exist_ok=True)
        token = secrets.token_hex(8)
        dest = upload_dir / f"{token}_{filename}"
        file.save(dest)
        result = run_scan(
            scan_name=scan_name,
            source_type="zip_upload",
            source_path=None,
            zip_path=str(dest),
            created_by=current_user.id if current_user.is_authenticated else None,
        )
    else:
        directory = (request.form.get("directory") or "").strip()
        if not directory:
            flash("Please enter a directory path.", "error")
            return redirect(url_for("scans.new"))
        result = run_scan(
            scan_name=scan_name,
            source_type="directory",
            source_path=directory,
            created_by=current_user.id if current_user.is_authenticated else None,
        )
    if result.status == "failed":
        flash(result.error_message or "Scan failed.", "error")
        return redirect(url_for("scans.new"))
    flash(
        f"Scan complete: {result.files_scanned} files, "
        f"{result.findings_count} findings.",
        "success",
    )
    return redirect(url_for("scans.detail", scan_id=result.scan_id))
@scans_bp.route("/<int:scan_id>")
@login_required
def detail(scan_id: int):
    scan = db.session.get(Scan, scan_id)
    if scan is None:
        abort(404)
    findings = db.session.execute(
        select(Finding)
        .where(Finding.scan_id == scan_id)
        .order_by(Finding.risk_score.desc(), Finding.id.desc())
    ).scalars().all()
    by_severity = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        key = (f.severity or "informational").lower()
        by_severity[key] = by_severity.get(key, 0) + 1
    return render_template(
        "scan_detail.html",
        scan=scan,
        findings=findings,
        by_severity=by_severity,
        severity_order=SEVERITY_ORDER,
    )
