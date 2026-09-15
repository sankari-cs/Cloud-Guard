"""Flask CLI commands for CloudGuard."""
from __future__ import annotations
import click
from flask.cli import with_appcontext
from app.extensions import db
from app.models.user import User
from app.security import validate_password_strength
def register_cli(app) -> None:
    @app.cli.command("init-db")
    @with_appcontext
    def init_db():
        """Create all database tables."""
        db.create_all()
        click.echo("Database initialized.")
    @app.cli.command("create-user")
    @click.option("--username", prompt=True)
    @click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
    @click.option("--role", default="viewer", type=click.Choice(["admin", "analyst", "viewer"]))
    @click.option("--email", default=None)
    @with_appcontext
    def create_user(username, password, role, email):
        """Create a new user."""
        ok, reason = validate_password_strength(password)
        if not ok:
            raise click.ClickException(reason)
        if User.query.filter_by(username=username).first():
            raise click.ClickException(f"User '{username}' already exists.")
        user = User(username=username, role=role, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        click.echo(f"Created user '{username}' with role '{role}'.")
    @app.cli.command("list-users")
    @with_appcontext
    def list_users():
        """List all users."""
        users = User.query.order_by(User.id).all()
        if not users:
            click.echo("No users.")
            return
        for u in users:
            click.echo(f"{u.id:>3}  {u.username:<20} {u.role:<10} active={u.is_active}")
    @app.cli.command("scan")
    @click.option("--name", required=True, help="Name for this scan.")
    @click.option("--path", required=True, help="Directory to scan.")
    @click.option("--user", "username", default=None, help="Username to attribute the scan to.")
    @with_appcontext
    def scan_cmd(name, path, username):
        """Run a scan against a directory and store findings."""
        from app.services.orchestrator import run_scan
        created_by = None
        if username:
            user = User.query.filter_by(username=username).first()
            if user is None:
                raise click.ClickException(f"User '{username}' not found.")
            created_by = user.id
        result = run_scan(
            scan_name=name,
            source_type="directory",
            source_path=path,
            created_by=created_by,
        )
        click.echo(
            f"status={result.status} "
            f"files={result.files_scanned} "
            f"findings={result.findings_count} "
            f"alerts={result.alerts_created}"
        )
        if result.error_message:
            click.echo(f"error={result.error_message}")
        for err in result.errors or []:
            click.echo(f"warning: {err}")
    @app.cli.command("scan-zip")
    @click.option("--name", required=True, help="Name for this scan.")
    @click.option("--zip", "zip_path", required=True, help="Path to a .zip file.")
    @click.option("--user", "username", default=None, help="Username to attribute the scan to.")
    @with_appcontext
    def scan_zip_cmd(name, zip_path, username):
        """Run a scan against a ZIP file and store findings."""
        from app.services.orchestrator import run_scan
        created_by = None
        if username:
            user = User.query.filter_by(username=username).first()
            if user is None:
                raise click.ClickException(f"User '{username}' not found.")
            created_by = user.id
        result = run_scan(
            scan_name=name,
            source_type="zip_upload",
            source_path=None,
            zip_path=zip_path,
            created_by=created_by,
        )
        click.echo(
            f"status={result.status} "
            f"files={result.files_scanned} "
            f"findings={result.findings_count} "
            f"alerts={result.alerts_created}"
        )
        if result.error_message:
            click.echo(f"error={result.error_message}")
        for err in result.errors or []:
            click.echo(f"warning: {err}")
