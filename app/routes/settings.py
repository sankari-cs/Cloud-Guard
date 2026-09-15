"""Settings page. Key/value overrides stored in the Setting table."""
from __future__ import annotations

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import login_required

from app.extensions import db
from app.models.setting import Setting

settings_bp = Blueprint("settings", __name__, url_prefix="/settings")

# Defaults shown when a key has no row yet.
DEFAULTS = {
    "max_upload_mb": "50",
    "max_files_per_scan": "5000",
    "max_findings_per_scan": "2000",
    "entropy_threshold": "3.5",
    "severity_critical": "85",
    "severity_high": "70",
    "severity_medium": "50",
    "severity_low": "25",
    "excluded_dirs": ".git,node_modules,.venv,__pycache__,dist,build",
}

# Fields the form is allowed to change.
EDITABLE_KEYS = tuple(DEFAULTS.keys())


def _load_settings() -> dict[str, str]:
    current = dict(DEFAULTS)
    for s in db.session.query(Setting).all():
        if s.key in DEFAULTS:
            current[s.key] = s.value if s.value is not None else ""
    return current


@settings_bp.route("/", methods=["GET", "POST"])
@login_required
def index():
    if request.method == "POST":
        for key in EDITABLE_KEYS:
            value = (request.form.get(key) or "").strip()
            row = db.session.query(Setting).filter_by(key=key).one_or_none()
            if row is None:
                row = Setting()
                row.key = key
                row.value = value
                db.session.add(row)
            else:
                row.value = value
        db.session.commit()
        flash("Settings saved.", "success")
        return redirect(url_for("settings.index"))

    current = _load_settings()
    return render_template("settings.html", settings=current)