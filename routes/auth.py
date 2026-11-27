from urllib.parse import urlparse
from email.message import EmailMessage
import smtplib

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from services.authentication import authenticate, log_action, register_user
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from models import db
from models.user import User
from services.rate_limit import limit

bp = Blueprint("auth", __name__)


def _reset_serializer():
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt="password-reset")


def _send_reset_email(user, token):
    host = current_app.config.get("SMTP_HOST")
    sender = current_app.config.get("MAIL_FROM")
    if not host or not sender:
        current_app.logger.error("Password reset requested but SMTP_HOST or MAIL_FROM is not configured")
        return
    link = url_for("auth.reset_password", token=token, _external=True)
    message = EmailMessage()
    message["Subject"] = "Reset your Config Audit password"
    message["From"] = sender
    message["To"] = user.email
    message.set_content(f"Use this link to reset your password (valid for one hour):\n\n{link}\n\nIf you did not request this, ignore this email.")
    try:
        with smtplib.SMTP(host, current_app.config.get("SMTP_PORT", 587), timeout=10) as smtp:
            if current_app.config.get("SMTP_USE_TLS", True):
                smtp.starttls()
            username = current_app.config.get("SMTP_USERNAME")
            if username:
                smtp.login(username, current_app.config.get("SMTP_PASSWORD", ""))
            smtp.send_message(message)
    except (OSError, smtplib.SMTPException):
        current_app.logger.exception("Could not send password reset email")


def _safe_next(target):
    """Only allow same-site relative redirects."""
    if target and target.startswith("/") and not target.startswith("//") \
            and not urlparse(target).netloc:
        return target
    return url_for("dashboard.index")


@bp.route("/register", methods=["GET", "POST"])
@limit("register", 5, 3600)
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))
    if request.method == "POST":
        try:
            register_user(request.form.get("username", "").strip(),
                          request.form.get("email", "").strip(),
                          request.form.get("password", ""))
        except ValueError as exc:
            flash(str(exc), "error")
        else:
            flash("Account created. Sign in to continue.", "success")
            return redirect(url_for("auth.login"))
    return render_template("register.html")


@bp.route("/login", methods=["GET", "POST"])
@limit("login", 10, 300)
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))
    if request.method == "POST":
        try:
            user = authenticate(request.form.get("identifier", ""), request.form.get("password", ""))
        except ValueError as exc:
            flash(str(exc), "error")
        else:
            if user:
                login_user(user, remember=request.form.get("remember") == "1")
                log_action("login", user_id=user.id)
                return redirect(_safe_next(request.args.get("next")))
            flash("Wrong username or password.", "error")
    return render_template("login.html")


@bp.route("/forgot-password", methods=["GET", "POST"])
@limit("forgot_password", 3, 3600)
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = User.query.filter(db.func.lower(User.email) == email).first() if email else None
        if user:
            token = _reset_serializer().dumps({"id": user.id, "hash": user.password_hash})
            _send_reset_email(user, token)
        flash("If an account exists for that email, password reset instructions have been sent.", "success")
        return redirect(url_for("auth.forgot_password"))
    return render_template("forgot_password.html")


@bp.route("/reset-password/<token>", methods=["GET", "POST"])
@limit("reset_password", 5, 3600)
def reset_password(token):
    try:
        payload = _reset_serializer().loads(token, max_age=current_app.config.get("PASSWORD_RESET_MAX_AGE", 3600))
    except (BadSignature, SignatureExpired):
        flash("This password reset link is invalid or has expired. Request a new one.", "error")
        return redirect(url_for("auth.forgot_password"))
    user = db.session.get(User, payload.get("id"))
    if not user or user.password_hash != payload.get("hash"):
        flash("This password reset link is invalid or has expired. Request a new one.", "error")
        return redirect(url_for("auth.forgot_password"))
    if request.method == "POST":
        password = request.form.get("password", "")
        confirmation = request.form.get("confirm_password", "")
        if password != confirmation:
            flash("Passwords do not match.", "error")
        elif len(password) < 8 or not any(c.isalpha() for c in password) or not any(c.isdigit() for c in password):
            flash("Password needs 8+ characters with letters and numbers.", "error")
        else:
            user.set_password(password)
            db.session.commit()
            log_action("password_reset", user_id=user.id)
            flash("Password updated. Sign in with your new password.", "success")
            return redirect(url_for("auth.login"))
    return render_template("reset_password.html")


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    log_action("logout")
    logout_user()
    return redirect(url_for("auth.login"))
