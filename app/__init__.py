"""CloudGuard application factory."""
from __future__ import annotations

from pathlib import Path

from flask import Flask, jsonify

from app.config import Config
from app.errors import register_error_handlers
from app.extensions import csrf, db, login_manager, migrate
from app.logging_config import configure_logging


def create_app(config_class: type[Config] = Config) -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Trusted hosts (allow localhost + test client)
    if app.config.get("TRUSTED_HOSTS"):
        app.config.setdefault("TRUSTED_HOSTS", app.config["TRUSTED_HOSTS"])

    for folder_key in ("UPLOAD_FOLDER", "REPORTS_FOLDER"):
        Path(app.config[folder_key]).mkdir(parents=True, exist_ok=True)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    migrate.init_app(app, db)

    with app.app_context():
        from app import models  # noqa: F401

    from app.models.user import User

    @login_manager.user_loader
    def load_user(user_id: str):
        try:
            return db.session.get(User, int(user_id))
        except (TypeError, ValueError):
            return None

    @app.after_request
    def set_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "script-src 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self'",
        )
        response.headers.setdefault(
            "Permissions-Policy",
            "geolocation=(), microphone=(), camera=()",
        )
        return response

    @app.route("/health")
    def health():
        return jsonify(status="ok", service="cloudguard"), 200

    # Register error handlers
    register_error_handlers(app)

    # Register blueprints
    from app.routes import (
        alerts_bp,
        auth_bp,
        dashboard_bp,
        findings_bp,
        reports_bp,
        scans_bp,
        settings_bp,
    )
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(findings_bp)
    app.register_blueprint(scans_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(settings_bp)

    # Register CLI commands
    from app.cli import register_cli
    register_cli(app)

    # Logging (with redaction filter)
    configure_logging()

    return app