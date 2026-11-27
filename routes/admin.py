from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user

from models import db
from models.audit_log import AuditLog
from models.user import User
from services.authentication import admin_required, log_action
from services.rate_limit import limit

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.route("/")
@admin_required
def index():
    users = User.query.order_by(User.id).all()
    logs = AuditLog.query.order_by(AuditLog.id.desc()).limit(100).all()
    return render_template("admin.html", users=users, logs=logs)


@bp.route("/users/<int:user_id>/role", methods=["POST"])
@limit("admin_role_change", 30, 3600)
@admin_required
def set_role(user_id):
    user = db.get_or_404(User, user_id)
    role = request.form.get("role")
    if role not in ("user", "admin"):
        flash("Unknown role.", "error")
    elif user.id == current_user.id:
        flash("You can't change your own role.", "error")
    else:
        user.role = role
        db.session.commit()
        log_action("role_changed", f"user={user.id} role={role}")
        flash(f"{user.username} is now {role}.", "success")
    return redirect(url_for("admin.index"))
