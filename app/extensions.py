"""Flask extension singletons. Initialized inside create_app()."""
from flask_login import LoginManager  # type: ignore[import-not-found]
from flask_migrate import Migrate  # type: ignore[import-not-found]
from flask_sqlalchemy import SQLAlchemy  # type: ignore[import-not-found]
from flask_wtf import CSRFProtect  # type: ignore[import-not-found]
db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
migrate = Migrate()
login_manager.login_view = "auth.login"
login_manager.login_message = "Please log in to continue."
login_manager.login_message_category = "warning"
