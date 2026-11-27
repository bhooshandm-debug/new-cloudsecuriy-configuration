import re
from datetime import timedelta
from functools import wraps

from flask import abort, request
from flask_login import current_user

from models import db, utcnow
from models.audit_log import AuditLog
from models.cloud_account import CloudAccount
from models.scan import Scan
from models.user import User

MAX_FAILED_LOGINS = 5
LOCKOUT_MINUTES = 15
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,40}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def log_action(action, detail="", user_id=None):
    if user_id is None and current_user and current_user.is_authenticated:
        user_id = current_user.id
    ip = request.remote_addr if request else ""
    db.session.add(AuditLog(user_id=user_id, action=action, detail=detail[:300], ip_address=ip or ""))
    db.session.commit()


def register_user(username, email, password):
    if not USERNAME_RE.match(username):
        raise ValueError("Username must be 3-40 characters: letters, numbers, . _ -")
    if not EMAIL_RE.match(email) or len(email) > 120:
        raise ValueError("Enter a valid email address.")
    if len(password) < 8 or not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        raise ValueError("Password needs 8+ characters with letters and numbers.")
    if User.query.filter(db.func.lower(User.username) == username.lower()).first() \
            or User.query.filter(db.func.lower(User.email) == email.lower()).first():
        raise ValueError("That username or email is already registered.")

    user = User(username=username, email=email.lower())
    user.set_password(password)
    user.role = "admin" if User.query.count() == 0 else "user"  # first user administers
    db.session.add(user)
    db.session.commit()
    log_action("register", f"role={user.role}", user_id=user.id)
    return user


def authenticate(identifier, password):
    """Return the User on success, None on bad credentials. Raises ValueError when locked out."""
    ident = (identifier or "").strip().lower()
    since = utcnow() - timedelta(minutes=LOCKOUT_MINUTES)
    # Lockout should not be bypassable by changing the username. The route also
    # has an IP based request limit; this per-identifier limit is an additional guard.
    failures = AuditLog.query.filter(AuditLog.action == "login_failed",
                                     AuditLog.detail == ident[:300],
                                     AuditLog.created_at > since).count()
    if failures >= MAX_FAILED_LOGINS:
        raise ValueError(f"Too many failed attempts. Try again in {LOCKOUT_MINUTES} minutes.")

    user = User.query.filter((db.func.lower(User.username) == ident) |
                             (db.func.lower(User.email) == ident)).first()
    if user and user.check_password(password or ""):
        return user
    log_action("login_failed", ident)
    return None


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(401)
        if not current_user.is_admin:
            abort(403)
        return view(*args, **kwargs)
    return wrapped


# ---- ownership scoping: users see their own data, admins see everything ----
def visible_accounts(user):
    q = CloudAccount.query
    return q if user.is_admin else q.filter_by(user_id=user.id)


def visible_scans(user):
    q = Scan.query
    return q if user.is_admin else q.filter_by(user_id=user.id)


def get_owned_or_404(model, obj_id):
    obj = db.get_or_404(model, obj_id)
    if not current_user.is_admin and obj.user_id != current_user.id:
        abort(404)
    return obj
