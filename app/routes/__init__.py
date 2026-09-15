"""Route blueprints."""
from app.routes.alerts import alerts_bp
from app.routes.auth import auth_bp
from app.routes.dashboard import dashboard_bp
from app.routes.findings import findings_bp
from app.routes.reports import reports_bp
from app.routes.scans import scans_bp
from app.routes.settings import settings_bp
__all__ = [
    "alerts_bp",
    "auth_bp",
    "dashboard_bp",
    "findings_bp",
    "reports_bp",
    "scans_bp",
    "settings_bp",
]
