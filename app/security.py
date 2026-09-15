"""Security helpers: password policy, role checks, audit logging, rate limit."""
from __future__ import annotations
import re
import time
from collections import defaultdict, deque
from functools import wraps
from flask import abort, request
from flask_login import current_user
from app.extensions import db
from app.models.audit_log import AuditLog
MIN_PASSWORD_LENGTH = 10
_PASSWORD_CLASSES = (
    re.compile(r"[a-z]"),
    re.compile(r"[A-Z]"),
    re.compile(r"\d"),
    re.compile(r"[^A-Za-z0-9]"),
)
def validate_password_strength(password: str) -> tuple[bool, str]:
    """Return (is_valid, reason). Enforces a minimal but realistic policy."""
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    classes = sum(1 for p in _PASSWORD_CLASSES if p.search(password))
    if classes < 3:
        return False, "Password must include at least 3 of: lowercase, uppercase, digit, symbol."
    return True, ""
def require_role(*roles: str):
    """Decorator: allow only users whose role is in `roles`."""
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            if current_user.role not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator
def record_audit(
    action: str,
    *,
    user_id: int | None = None,
    target_type: str | None = None,
    target_id: int | None = None,
) -> None:
    """Append an AuditLog row. Safe to call even outside a request."""
    try:
        ip = request.remote_addr if request else None
        ua = request.user_agent.string[:255] if request and request.user_agent else None
    except RuntimeError:
        ip = None
        ua = None
    log = AuditLog(
        user_id=user_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        ip_address=ip,
        user_agent=ua,
    )
    db.session.add(log)
    db.session.commit()
# ---------- login rate limiting ----------
_FAILED_LOGINS: dict[str, deque] = defaultdict(deque)
MAX_FAILURES = 5
WINDOW_SECONDS = 300
def record_failed_login(key: str) -> None:
    """Record one failed login attempt for a key (typically the IP)."""
    now = time.time()
    q = _FAILED_LOGINS[key]
    q.append(now)
    while q and now - q[0] > WINDOW_SECONDS:
        q.popleft()
def is_rate_limited(key: str) -> bool:
    """True if the key has exceeded MAX_FAILURES within WINDOW_SECONDS."""
    now = time.time()
    q = _FAILED_LOGINS.get(key)
    if not q:
        return False
    while q and now - q[0] > WINDOW_SECONDS:
        q.popleft()
    return len(q) >= MAX_FAILURES
def clear_failed_logins(key: str) -> None:
    """Clear the failure record for a key. Called on successful login."""
    _FAILED_LOGINS.pop(key, None)
__all__ = [
    "validate_password_strength",
    "require_role",
    "record_audit",
    "record_failed_login",
    "is_rate_limited",
    "clear_failed_logins",
]
