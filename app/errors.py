"""Centralized error handlers."""
from __future__ import annotations
import logging
from flask import Flask, render_template, request
from werkzeug.exceptions import HTTPException
logger = logging.getLogger(__name__)
# Codes we have templates for.
SUPPORTED = (400, 401, 403, 404, 500)
def _render(code: int, title: str):
    template = f"errors/{code}.html" if code in SUPPORTED else "errors/500.html"
    return render_template(template, title=title), code
def register_error_handlers(app: Flask) -> None:
    @app.errorhandler(400)
    def bad_request(_e):
        return _render(400, "Bad request")
    @app.errorhandler(401)
    def unauthorized(_e):
        return _render(401, "Unauthorized")
    @app.errorhandler(403)
    def forbidden(_e):
        return _render(403, "Forbidden")
    @app.errorhandler(404)
    def not_found(_e):
        return _render(404, "Not found")
    @app.errorhandler(500)
    def server_error(_e):
        logger.error("internal error path=%s", request.path)
        return _render(500, "Internal server error")
    @app.errorhandler(HTTPException)
    def http_error(e: HTTPException):
        code = e.code or 500
        if code in SUPPORTED:
            return _render(code, e.name or "Error")
        return _render(500, "Error")
