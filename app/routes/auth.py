"""Authentication routes."""
from __future__ import annotations
from datetime import datetime, timezone
from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user
from app.extensions import db
from app.models.user import User
from app.security import (
    clear_failed_logins,
    is_rate_limited,
    record_audit,
    record_failed_login,
)
auth_bp = Blueprint("auth", __name__)
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))
    if request.method == "POST":
        ip = request.remote_addr or "unknown"
        if is_rate_limited(ip):
            flash("Too many failed attempts. Try again later.", "error")
            return render_template("login.html"), 429
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        user = User.query.filter_by(username=username).first()
        if user is None or not user.check_password(password) or not user.is_active:
            record_failed_login(ip)
            flash("Invalid username or password.", "error")
            record_audit(
                "login_failed",
                target_type="user",
                target_id=user.id if user else None,
            )
            return render_template("login.html"), 401
        clear_failed_logins(ip)
        login_user(user, remember=False)
        user.last_login_at = datetime.now(timezone.utc)
        db.session.commit()
        record_audit(
            "login_success",
            user_id=user.id,
            target_type="user",
            target_id=user.id,
        )
        next_url = request.args.get("next")
        if next_url and next_url.startswith("/"):
            return redirect(next_url)
        return redirect(url_for("dashboard.index"))
    return render_template("login.html")
@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    user_id = current_user.id
    logout_user()
    record_audit("logout", user_id=user_id, target_type="user", target_id=user_id)
    flash("Signed out.", "success")
    return redirect(url_for("auth.login"))
