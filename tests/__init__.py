"""Route blueprints."""
from app.routes.auth import auth_bp
from app.routes.dashboard import dashboard_bp
from app.routes.findings import findings_bp
from app.routes.scans import scans_bp

__all__ = ["auth_bp", "dashboard_bp", "findings_bp", "scans_bp"]